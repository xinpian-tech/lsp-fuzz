use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::BufWriter,
    ops::Not,
    path::PathBuf,
    time::Duration,
};

use anyhow::Context;
use clap::builder::BoolishValueParser;
use libafl::{
    Fuzzer, NopInputFilter, StdFuzzerBuilder,
    corpus::Corpus,
    events::SimpleEventManager,
    feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback},
    monitors::SimpleMonitor,
    mutators::HavocScheduledMutator,
    observers::{
        AsanBacktraceObserver, CanTrack, HitcountsMapObserver, StdMapObserver, TimeObserver,
    },
    schedulers::{QueueScheduler, powersched::BaseSchedule},
    stages::{CalibrationStage, StdMutationalStage, StdPowerMutationalStage},
    state::{HasCorpus, StdState},
};
use libafl_bolts::{
    AsSliceMut, HasLen,
    rands::StdRand,
    shmem::{ShMem, ShMemProvider, StdShMemProvider},
};
use lsp_fuzz::{
    corpus::{
        TestCaseFileNameFeedback,
        corpus_kind::{CORPUS, SOLUTION},
    },
    execution::{
        FuzzExecutionConfig, FuzzInput, LspExecutor, jvm, jvm_executor,
        responses::LspOutputObserver, workspace_observer::WorkspaceObserver,
    },
    fuzz_target,
    lsp::GeneratorsConfig,
    lsp_input::{
        JvmLspInputConverter, LspInputBytesConverter, LspInputGenerator, LspInputMutator,
        messages::message_mutations, server_response::LspResponseFeedback,
    },
    stages::{StatsStage, TimeoutStopStage},
    text_document::text_document_mutations,
    utf8::UTF8Tokens,
};
use lsp_fuzz_grammars::Language;
use memmap2::Mmap;
use tracing::info;
use tuple_list::tuple_list;

use super::{GlobalOptions, parse_hash_map};
use crate::{
    fuzzing::{
        ExecutorOptions, FuzzerStateDir,
        common::{self},
    },
    language_fragments::load_grammar_lookup,
};

const INPUT_SHM_SIZE: usize = 15 * 1024 * 1024 * 1024;

/// Fuzz a Language Server Protocol (LSP) server.
#[derive(Debug, clap::Parser)]
pub(super) struct FuzzCommand {
    /// Directory containing the fuzzer states.
    #[clap(long)]
    state: FuzzerStateDir,

    /// Enable auto tokens.
    #[clap(long, env = "AFL_NO_AUTODICT", value_parser = BoolishValueParser::new())]
    no_auto_dict: bool,

    /// Number of seeds to generate if no seeds are provided.
    #[clap(long, default_value_t = 32)]
    generate_seeds: usize,

    #[clap(flatten)]
    execution: ExecutorOptions,

    /// The path to the temporary directory.
    #[clap(long, env = "AFL_TMPDIR")]
    temp_dir: Option<PathBuf>,

    /// Power schedule to use for fuzzing.
    #[clap(long, short, value_enum, default_value_t = BaseSchedule::FAST)]
    power_schedule: BaseSchedule,

    /// Whether to cycle power schedules.
    #[clap(long, env = "AFL_CYCLE_SCHEDULES", value_parser = BoolishValueParser::new())]
    cycle_power_schedule: bool,

    /// Bind the fuzzer to a specific CPU core.
    #[clap(long)]
    cpu_affinity: Option<usize>,

    /// Stop fuzzing after a certain number of hours.
    #[clap(long)]
    time_budget: u64,

    #[clap(long)]
    no_asan: bool,

    #[clap(long, value_parser = parse_hash_map::<Language, PathBuf>, default_value = "")]
    language_fragments: HashMap<Language, PathBuf>,

    /// Fuzz a JVM language-server target through the persistent coverage worker instead of the
    /// native AFL fork server. Give the full worker argv (the program then its arguments), e.g.
    /// `--jvm-worker java -cp out cov.Worker`. When present, the native ELF/AFL binary checks and
    /// `--lsp-executable` are skipped; each token is preserved as a separate argv entry.
    ///
    /// Because the argv is variadic and accepts hyphen-prefixed tokens, it greedily consumes
    /// everything after it. Put other fuzz options (e.g. `--scala-mode`) BEFORE `--jvm-worker`, or
    /// terminate the worker argv with a `;` token so later options are parsed normally, e.g.
    /// `--jvm-worker java -cp out cov.Worker ';' --scala-mode index`.
    #[clap(long, num_args = 1.., allow_hyphen_values = true, value_terminator = ";")]
    jvm_worker: Vec<String>,

    /// The Scala language-server mode for JVM fuzzing: `pc` (presentation compiler, the default) or
    /// `index` (BSP-backed index paths; requires the pinned native `SQLite` and a verified backdrop).
    #[clap(long, value_enum, default_value_t)]
    scala_mode: lsp_fuzz::execution::scala_profile::ScalaProfileMode,
}

impl FuzzCommand {
    #[allow(
        clippy::too_many_lines,
        reason = "Need to put in one method for type inference"
    )]
    pub(super) fn run(self, global_options: GlobalOptions) -> Result<(), anyhow::Error> {
        self.state.create().context("Crating state dir")?;
        // A JVM target is driven through a persistent coverage worker, not the AFL fork server, so
        // it must not go through the native ELF/AFL binary inspection below.
        if !self.jvm_worker.is_empty() {
            // The variadic worker argv greedily consumes hyphen-prefixed tokens, so a fuzz option
            // placed after `--jvm-worker` is silently swallowed into the worker argv (leaving, e.g.,
            // `scala_mode` at its default). `--scala-mode` never belongs in a JVM worker command, so
            // finding it there means it was swallowed — fail loudly instead of running misconfigured.
            if let Some(pos) = self
                .jvm_worker
                .iter()
                .position(|a| a == "--scala-mode" || a.starts_with("--scala-mode="))
            {
                anyhow::bail!(
                    "`--scala-mode` was consumed as --jvm-worker argv (token {pos}) and silently \
                     ignored. Put fuzz options before --jvm-worker, or terminate the worker argv \
                     with a ';' token, e.g. `--jvm-worker java -cp out cov.Worker ';' --scala-mode index`."
                );
            }
            return self.run_jvm_mode(global_options);
        }
        // Native fork-server mode requires a target binary; the JVM branch above does not.
        let lsp_executable = self
            .execution
            .lsp_executable
            .clone()
            .context("--lsp-executable is required for native fuzzing (or use --jvm-worker)")?;
        let mut shmem_provider =
            StdShMemProvider::new().context("Creating shared memory provider")?;

        let binary_info = Self::check_binary(&lsp_executable).context("Checking binary")?;
        let map_size = fuzz_target::dump_map_size(&lsp_executable).context("Dumping map size")?;
        info!("Detected coverage map size: {}", map_size);

        let mut coverage_shmem = shmem_provider
            .new_shmem(map_size)
            .context("Creating shared memory")?;
        let coverage_map_shmem_id = coverage_shmem.id();

        info!("Loading grammar context");
        let grammar_ctx =
            load_grammar_lookup(&self.language_fragments).context("Creating grammar context")?;

        let coverage_map_observer = {
            let shmem_buf = coverage_shmem.as_slice_mut();
            // SAFETY: We never move the piece of the shared memory.
            unsafe { StdMapObserver::new("edges", shmem_buf) }
        };

        let lsp_response_observer = LspOutputObserver::new();
        let asan_observer = AsanBacktraceObserver::new("asan_stacktrace");

        let asan_enabled = binary_info.uses_address_sanitizer && self.no_asan.not();
        let cov_observer = HitcountsMapObserver::new(coverage_map_observer).track_indices();

        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");

        let map_feedback = MaxMapFeedback::new(&cov_observer);
        let calibration_stage = CalibrationStage::new(&map_feedback);
        let stats_stage = {
            let stats_writer = self
                .create_stats_writer()
                .context("Creating stats writer")?;
            StatsStage::new(stats_writer, &map_feedback)
        };

        let mut feedback = feedback_or!(
            map_feedback,
            LspResponseFeedback::new(&lsp_response_observer),
            TestCaseFileNameFeedback::<CORPUS>::new(),
            TimeFeedback::new(&time_observer)
        );

        let mut objective = common::objective(asan_enabled, &asan_observer);

        let (corpus, solutions) =
            common::create_corpus(&self.state.corpus_dir(), &self.state.solution_dir())
                .context("Creating corpus")?;

        let random_seed = global_options
            .random_seed
            .unwrap_or_else(libafl_bolts::current_nanos);
        let rand = StdRand::with_seed(random_seed);
        let mut state = StdState::new(rand, corpus, solutions, &mut feedback, &mut objective)
            .context("Creating state")?;

        let mut tokens = self.no_auto_dict.not().then(UTF8Tokens::new);

        let scheduler = common::scheduler(
            &mut state,
            &cov_observer,
            self.power_schedule,
            self.cycle_power_schedule,
        );
        let temp_dir = self.temp_dir.unwrap_or_else(std::env::temp_dir);

        // A fuzzer with feedback and a corpus scheduler
        let mut fuzzer = StdFuzzerBuilder::new()
            .input_filter(NopInputFilter)
            .target_bytes_converter(LspInputBytesConverter::new(temp_dir.clone()))
            .scheduler(scheduler)
            .feedback(feedback)
            .objective(objective)
            .build();

        let mut fuzz_stages = {
            let mutation_stage = {
                let generators_config = GeneratorsConfig::full();
                let text_document_mutator = HavocScheduledMutator::with_max_stack_pow(
                    text_document_mutations(&grammar_ctx, &generators_config),
                    6,
                );
                let messages_mutator = HavocScheduledMutator::with_max_stack_pow(
                    message_mutations(&generators_config),
                    3,
                );
                let mutator = LspInputMutator::new(text_document_mutator, messages_mutator);
                StdPowerMutationalStage::new(mutator)
            };
            let trigger_stop = common::trigger_stop_stage()?;
            let timeout_stop = TimeoutStopStage::new(Duration::from_hours(self.time_budget));
            tuple_list![
                calibration_stage,
                mutation_stage,
                stats_stage,
                timeout_stop,
                trigger_stop,
            ]
        };

        let asan_observer = asan_enabled.then_some(asan_observer);
        if asan_observer.is_some() {
            info!("Crash stack hashing will be enabled");
        }
        let mut executor = {
            let test_case_shmem = shmem_provider
                .new_shmem(INPUT_SHM_SIZE)
                .context("Creating shared memory for test case passing")?;
            let fuzz_input = FuzzInput::SharedMemory(test_case_shmem);
            let target_info =
                common::create_target_info(&self.execution, &binary_info, lsp_executable.clone());
            let workspace_observer = WorkspaceObserver::new(temp_dir);
            let exec_config = FuzzExecutionConfig {
                debug_child: self.execution.debug_child,
                debug_afl: self.execution.debug_afl,
                fuzz_input,
                auto_tokens: tokens.as_mut(),
                coverage_shm_info: (coverage_map_shmem_id, cov_observer.as_ref().len()),
                map_observer: cov_observer,
                responses_observer: lsp_response_observer,
                asan_observer,
                other_observers: tuple_list![workspace_observer, time_observer],
            };
            LspExecutor::start(target_info, exec_config).context("Starting executor")?
        };

        common::process_tokens(&mut state, tokens);

        let mut event_manager = {
            let monitor = SimpleMonitor::new(|it| info!("{}", it));
            SimpleEventManager::new(monitor)
        };

        // In case the corpus is empty (on first run), reset
        if state.must_load_initial_inputs() {
            info!("Generating seeds");
            let mut generator = LspInputGenerator::new(&grammar_ctx);
            state
                .generate_initial_inputs_forced(
                    &mut fuzzer,
                    &mut executor,
                    &mut generator,
                    &mut event_manager,
                    self.generate_seeds,
                )
                .context("Generating initial input")?;
            info!(seeds = %state.corpus().count(), "Seed generation completed");
        }

        common::set_cpu_affinity(self.cpu_affinity);

        let fuzz_result = fuzzer.fuzz_loop(
            &mut fuzz_stages,
            &mut executor,
            &mut state,
            &mut event_manager,
        );

        match fuzz_result {
            Ok(()) => unreachable!("The fuzz loop will never exit with Ok"),
            Err(libafl::Error::ShuttingDown) => {
                info!(
                    "Stop requested by user. {} will now exit.",
                    crate::PROGRAM_NAME
                );
                Ok(())
            }
            err @ Err(_) => err.context("In fuzz loop"),
        }
    }

    /// Fuzz a JVM language-server target through the persistent coverage worker. No native ELF/AFL
    /// binary inspection: coverage comes from the worker's mmap map surfaced through
    /// [`JvmLspExecutor`], and crashes are the fuzzing objective.
    #[allow(
        clippy::too_many_lines,
        reason = "single method for LibAFL type inference"
    )]
    fn run_jvm_mode(self, global_options: GlobalOptions) -> Result<(), anyhow::Error> {
        let (program, args) = self
            .jvm_worker
            .split_first()
            .context("--jvm-worker must name a worker program")?;
        let program = program.clone();
        let args = args.to_vec();

        // Honor `--target-env` for the JVM path the same way native mode does. These vars (e.g. index
        // mode's `LS_SQLITE_LIB` / `BACKDROP_OUT`) are read from the PROCESS environment by the profile
        // validation below, the backdrop converter (`JvmLspInputConverter` reads `BACKDROP_OUT`), and
        // the worker (which inherits it), so apply them to the process env up front — before any of
        // those reads and before any worker/thread is spawned.
        for (key, value) in &self.execution.target_env {
            // SAFETY: run at CLI startup on the main thread, before the fuzz loop spawns any worker
            // or thread, so there is no concurrent environment access.
            unsafe {
                std::env::set_var(key, value);
            }
        }

        // The Scala execution profile isolates the language-server mode (init params, capabilities,
        // per-mode method allowlist). Index mode needs its native SQLite + verified backdrop.
        let profile =
            lsp_fuzz::execution::scala_profile::ScalaExecutionProfile::for_mode(self.scala_mode);
        profile
            .validate_environment()
            .map_err(|e| anyhow::anyhow!(e))
            .context("The requested Scala mode is missing required environment")?;

        // The Scala fuzzing configuration must launch the language server under the determinism
        // flags so coverage is stable across identical inputs (see docs/jvm-coverage-agent.md). The
        // worker argv is operator-supplied, so enforce the flags here rather than silently fuzzing
        // under a non-deterministic JVM.
        let missing = profile.missing_determinism_flags(&self.jvm_worker);
        if !missing.is_empty() {
            anyhow::bail!(
                "the --jvm-worker launch is missing required determinism flags {missing:?}; \
                 add them to the worker command (e.g. `java {} -javaagent:… -cp … cov.Worker`)",
                profile.determinism_flags().join(" ")
            );
        }

        let grammar_ctx =
            load_grammar_lookup(&self.language_fragments).context("Creating grammar context")?;

        let temp_dir = self.temp_dir.clone().unwrap_or_else(std::env::temp_dir);
        let map_path = temp_dir.join(format!("jvm-cov-{}.bin", std::process::id()));
        // The worker publishes JSON-RPC error responses (findings) at $COV_FINDINGS_PATH; the
        // executor's outcome observer reads them after each run.
        let findings_path = temp_dir.join(format!("jvm-findings-{}.tsv", std::process::id()));

        // The profile's timeout policy governs the worker: the per-input run budget and quiescence
        // deadline are passed as env, and the Rust reply deadline is derived from them (not
        // hard-coded), so index mode actually gets its longer settling windows.
        let run_timeout_ms = profile.run_timeout_ms();
        let quiescence_deadline_ms = profile.quiescence_deadline_ms();
        let worker_reply_deadline = profile.worker_reply_deadline();

        // The worker embeds the real in-process Scala language server when `COV_ITERATION_BODY=ls`;
        // without it `cov.Worker` defaults to the planted fixture body, so a Scala fuzzing run must
        // select `ls`. Default to it here (this spawn path owns the worker env), but respect an
        // explicit operator override in the environment (e.g. the JVM smoke drives the fixture worker).
        let iteration_body =
            std::env::var("COV_ITERATION_BODY").unwrap_or_else(|_| "ls".to_string());

        // The worker publishes its coverage map at $COV_MAP_PATH; the executor copies from there.
        let target_env = self.execution.target_env.clone();
        let spawn_worker = {
            let program = program.clone();
            let args = args.clone();
            let map_path = map_path.clone();
            let findings_path = findings_path.clone();
            let iteration_body = iteration_body.clone();
            move || {
                let mut command = std::process::Command::new(&program);
                command
                    .args(&args)
                    // The operator's `--target-env` (e.g. LS_SQLITE_LIB / BACKDROP_OUT), applied
                    // explicitly on the worker command as well as the process env above.
                    .envs(&target_env)
                    .env("COV_ITERATION_BODY", &iteration_body)
                    .env("COV_MAP_PATH", &map_path)
                    .env("COV_FINDINGS_PATH", &findings_path)
                    .env("COV_RUN_TIMEOUT_MS", run_timeout_ms.to_string())
                    .env(
                        "COV_QUIESCE_DEADLINE_MS",
                        quiescence_deadline_ms.to_string(),
                    );
                jvm::SubprocessTransport::spawn(command)
            }
        };
        let transport = spawn_worker().context("Spawning JVM worker")?;
        let worker = jvm::JvmWorker::new(transport, &map_path, worker_reply_deadline);

        let cov_observer = jvm_executor::jvm_coverage_observer("jvm-edges");
        let outcome_observer = jvm_executor::JvmOutcomeObserver::new(Some(findings_path.clone()));
        let map_feedback = MaxMapFeedback::new(&cov_observer);
        // Export a provenanced finding bundle for every finding run. Provenance is read from the
        // environment; when required fields are absent the export fails closed (logs + skips), so a
        // finding is never written without enough metadata for a one-command cold replay.
        let make_finding_export = || {
            let provenance = lsp_fuzz::finding_bundle::Provenance::from_env(
                self.scala_mode.as_str(),
                run_timeout_ms,
            );
            let bundle_dir = self.state.solution_dir().join("finding-bundles");
            lsp_fuzz::finding_bundle::JvmFindingExportFeedback::new(
                &outcome_observer,
                provenance,
                bundle_dir,
            )
        };
        let mut feedback = feedback_or!(
            map_feedback,
            make_finding_export(),
            TestCaseFileNameFeedback::<CORPUS>::new()
        );
        // A crash-class JVM finding (FatalJvmError / OOM / stack overflow / foreground exception)
        // makes the OBJECTIVE interesting, and LibAFL does not run the corpus `feedback` chain for a
        // solution — so the bundle export must also run on the objective path, or those findings would
        // be saved as solutions with no provenanced bundle. A second exporter here covers that; the
        // export is idempotent (one bundle per finding, keyed by the input hash), so a finding that
        // trips both paths is written once, not corrupted.
        let mut objective = feedback_or!(
            TestCaseFileNameFeedback::<SOLUTION>::new(),
            CrashFeedback::new(),
            make_finding_export()
        );

        let (corpus, solutions) =
            common::create_corpus(&self.state.corpus_dir(), &self.state.solution_dir())
                .context("Creating corpus")?;
        let random_seed = global_options
            .random_seed
            .unwrap_or_else(libafl_bolts::current_nanos);
        let mut state = StdState::new(
            StdRand::with_seed(random_seed),
            corpus,
            solutions,
            &mut feedback,
            &mut objective,
        )
        .context("Creating state")?;

        let mut fuzzer = StdFuzzerBuilder::new()
            .input_filter(NopInputFilter)
            .target_bytes_converter(JvmLspInputConverter::new(temp_dir, profile.clone()))
            .scheduler(QueueScheduler::new())
            .feedback(feedback)
            .objective(objective)
            .build();

        let mut executor = jvm_executor::JvmLspExecutor::with_observers(
            worker,
            spawn_worker,
            cov_observer,
            outcome_observer,
        );

        let mut fuzz_stages = {
            // The profile's invalid-message policy controls whether generation emits invalid
            // positions/ranges/params.
            let generators_config = profile.apply_generation_policy(GeneratorsConfig::full());
            let text_document_mutator = HavocScheduledMutator::with_max_stack_pow(
                text_document_mutations(&grammar_ctx, &generators_config),
                6,
            );
            let messages_mutator =
                HavocScheduledMutator::with_max_stack_pow(message_mutations(&generators_config), 3);
            let mutator = LspInputMutator::new(text_document_mutator, messages_mutator);
            let mutation_stage = StdMutationalStage::new(mutator);
            let timeout_stop = TimeoutStopStage::new(Duration::from_hours(self.time_budget));
            let trigger_stop = common::trigger_stop_stage()?;
            tuple_list![mutation_stage, timeout_stop, trigger_stop]
        };

        let mut event_manager = SimpleEventManager::new(SimpleMonitor::new(|it| info!("{}", it)));

        if state.must_load_initial_inputs() {
            info!("Generating seeds");
            let mut generator = LspInputGenerator::new(&grammar_ctx);
            state
                .generate_initial_inputs_forced(
                    &mut fuzzer,
                    &mut executor,
                    &mut generator,
                    &mut event_manager,
                    self.generate_seeds,
                )
                .context("Generating initial input")?;
        }

        common::set_cpu_affinity(self.cpu_affinity);

        match fuzzer.fuzz_loop(
            &mut fuzz_stages,
            &mut executor,
            &mut state,
            &mut event_manager,
        ) {
            Ok(()) => unreachable!("The fuzz loop will never exit with Ok"),
            Err(libafl::Error::ShuttingDown) => {
                info!("Stop requested. {} will now exit.", crate::PROGRAM_NAME);
                Ok(())
            }
            err @ Err(_) => err.context("In JVM fuzz loop"),
        }
    }

    fn check_binary(
        lsp_executable: &std::path::Path,
    ) -> Result<fuzz_target::StaticTargetBinaryInfo, anyhow::Error> {
        let binary_file = File::open(lsp_executable).context("Opening fuzz target")?;
        // SAFETY: we are assuming that the file is not touched externally.
        let binary_file = unsafe { Mmap::map(&binary_file) }.context("Mapping fuzz target")?;
        common::analyze_fuzz_target(&binary_file)
    }

    fn create_stats_writer(&self) -> Result<BufWriter<File>, anyhow::Error> {
        let stats_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(self.state.stats_file())
            .context("Creating stats file")?;
        Ok(BufWriter::new(stats_file))
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::FuzzCommand;

    /// A JVM-worker invocation must parse WITHOUT `--lsp-executable`, and `--jvm-worker` must
    /// preserve the worker argv verbatim (program + hyphenated flags), not whitespace-split it.
    #[test]
    fn jvm_mode_parses_without_lsp_executable_and_preserves_argv() {
        let parsed = FuzzCommand::try_parse_from([
            "fuzz",
            "--state",
            "/tmp/lsp-fuzz-parse-test",
            "--time-budget",
            "0",
            "--jvm-worker",
            "java",
            "-cp",
            "out dir",
            "cov.Worker",
        ])
        .expect("JVM mode should parse without --lsp-executable");
        assert!(
            parsed.execution.lsp_executable.is_none(),
            "native --lsp-executable must be optional in JVM mode"
        );
        assert_eq!(
            parsed.jvm_worker,
            vec![
                "java".to_owned(),
                "-cp".to_owned(),
                "out dir".to_owned(), // a spaced arg that whitespace-splitting would break
                "cov.Worker".to_owned(),
            ],
            "worker argv must be preserved token-for-token"
        );
    }

    /// The native (non-JVM) invocation still parses with a target and leaves `--jvm-worker` empty.
    #[test]
    fn native_mode_parses_with_lsp_executable() {
        let parsed = FuzzCommand::try_parse_from([
            "fuzz",
            "--state",
            "/tmp/lsp-fuzz-parse-test",
            "--time-budget",
            "0",
            "--lsp-executable",
            "/path/to/server",
        ])
        .expect("native mode should parse with --lsp-executable");
        assert!(parsed.jvm_worker.is_empty());
        assert!(parsed.execution.lsp_executable.is_some());
    }
}
