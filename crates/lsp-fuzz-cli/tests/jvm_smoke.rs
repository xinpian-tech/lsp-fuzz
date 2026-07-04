//! Bounded live smoke for the JVM `fuzz` mode: run the built CLI against the compiled Java fixture
//! worker with a tiny seed count and an immediate stop, and assert it reaches the JVM fuzz loop
//! (seed generation drives the worker through `JvmLspExecutor`) and exits without deadlocking —
//! without any native `--lsp-executable`. Skips when the JDK is unavailable.

use std::{
    path::Path,
    process::Command,
    thread,
    time::{Duration, Instant},
};

fn javac_available() -> bool {
    Command::new("javac")
        .arg("-version")
        .status()
        .is_ok_and(|s| s.success())
}

/// Panic (not skip) when a checked-in Java source is missing: a repository/source-list regression,
/// not an unavailable external toolchain. Lists every missing path.
fn assert_sources_present(sources: &[String]) {
    let missing: Vec<&str> = sources
        .iter()
        .filter(|s| !Path::new(s).exists())
        .map(String::as_str)
        .collect();
    assert!(
        missing.is_empty(),
        "checked-in Java worker sources are missing:\n{}",
        missing.join("\n")
    );
}

/// Write the minimal marker layout `validate_backdrop_root` requires, so a test can point
/// `BACKDROP_OUT` at a valid frozen backdrop without a real zaozi checkout.
fn write_fake_backdrop(root: &Path) {
    std::fs::write(root.join("backdrop-metadata.json"), b"{}").unwrap();
    std::fs::create_dir_all(root.join("bsp")).unwrap();
    std::fs::write(root.join("bsp").join("mill-bsp.json"), b"{}").unwrap();
    std::fs::create_dir_all(root.join("semanticdb").join("pkg")).unwrap();
    std::fs::write(
        root.join("semanticdb")
            .join("pkg")
            .join("X.scala.semanticdb"),
        b"sdb",
    )
    .unwrap();
}

/// In JVM index mode, the required env supplied via `--target-env` (not the ambient process env) must
/// satisfy the profile validation — proving `--target-env` is honored on the JVM path like native
/// mode. The run then fails later (spawning the bogus worker program), NOT with a missing-required-
/// environment error. Needs no JDK: it never reaches a real worker.
#[test]
fn jvm_index_mode_honors_target_env_for_required_vars() {
    let backdrop = tempfile::tempdir().expect("tempdir");
    write_fake_backdrop(backdrop.path());
    let state = tempfile::tempdir().expect("tempdir");
    let output = Command::new(env!("CARGO_BIN_EXE_lsp-fuzz-cli"))
        .args([
            "fuzz",
            "--state",
            state.path().to_str().unwrap(),
            "--time-budget",
            "0",
            "--scala-mode",
            "index",
            // Both index-required vars supplied ONLY via --target-env (not the ambient env).
            "--target-env",
            &format!(
                "LS_SQLITE_LIB=/nonexistent/libsqlite3.so,BACKDROP_OUT={}",
                backdrop.path().display()
            ),
            // Determinism flags before the main class; the program does not exist so the run fails at
            // spawn — AFTER passing environment + determinism validation.
            "--jvm-worker",
            "/nonexistent/java",
            "-XX:-UseCompactObjectHeaders",
            "-Xshare:off",
            "-XX:+UseSerialGC",
            "-cp",
            "/nonexistent/ls.jar",
            "cov.Worker",
        ])
        .output()
        .expect("run CLI");
    assert!(
        !output.status.success(),
        "the bogus worker program must make the run fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("missing required environment")
            && !stderr.contains("LS_SQLITE_LIB environment variable")
            && !stderr.contains("BACKDROP_OUT environment variable"),
        "required env supplied via --target-env must satisfy validation; got:\n{stderr}"
    );
}

/// A JVM-mode `fuzz` launch whose `--jvm-worker` argv omits the determinism flags is rejected
/// before any worker is spawned (so this needs no JDK): the Scala fuzzing config must run the server
/// deterministically. Complements the happy-path smoke below, which DOES pass the flags.
#[test]
fn jvm_mode_rejects_worker_argv_without_determinism_flags() {
    let state = tempfile::tempdir().expect("tempdir");
    let output = Command::new(env!("CARGO_BIN_EXE_lsp-fuzz-cli"))
        .args([
            "fuzz",
            "--state",
            state.path().to_str().unwrap(),
            "--time-budget",
            "0",
            "--scala-mode",
            "pc",
            "--jvm-worker",
            "java",
            "-cp",
            "/nonexistent/ls.jar",
            "cov.Worker",
        ])
        .output()
        .expect("run CLI");
    assert!(
        !output.status.success(),
        "a worker argv missing the determinism flags must be rejected"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("determinism") && stderr.contains("UseCompactObjectHeaders"),
        "the error must name the missing determinism flags; got:\n{stderr}"
    );
}

/// A fuzz option placed AFTER `--jvm-worker` is greedily swallowed into the variadic worker argv.
/// The CLI must reject this loudly (needs no JDK: the guard fires before any worker is spawned)
/// rather than silently running with `scala_mode` at its default.
#[test]
fn jvm_worker_swallowing_a_fuzz_option_is_rejected() {
    let state = tempfile::tempdir().expect("tempdir");
    let output = Command::new(env!("CARGO_BIN_EXE_lsp-fuzz-cli"))
        .args([
            "fuzz",
            "--state",
            state.path().to_str().unwrap(),
            "--time-budget",
            "0",
            "--jvm-worker",
            "java",
            "-cp",
            "/nonexistent/ls.jar",
            "cov.Worker",
            // Placed after --jvm-worker → swallowed into the worker argv.
            "--scala-mode",
            "index",
        ])
        .output()
        .expect("run CLI");
    assert!(
        !output.status.success(),
        "a --scala-mode swallowed into the worker argv must be rejected"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--scala-mode") && stderr.contains("jvm-worker"),
        "the error must explain the swallowed --scala-mode; got:\n{stderr}"
    );
}

/// A `;` terminator ends the worker argv so later options are parsed normally: `--scala-mode` is no
/// longer swallowed (the guard does not fire) and the run proceeds to the determinism-flag check.
#[test]
fn jvm_worker_terminator_lets_later_options_parse() {
    let state = tempfile::tempdir().expect("tempdir");
    let output = Command::new(env!("CARGO_BIN_EXE_lsp-fuzz-cli"))
        .args([
            "fuzz",
            "--state",
            state.path().to_str().unwrap(),
            "--time-budget",
            "0",
            "--jvm-worker",
            "java",
            "-cp",
            "/nonexistent/ls.jar",
            "cov.Worker",
            ";",
            "--scala-mode",
            // `pc` has no required env, so the run deterministically reaches the determinism gate
            // (index mode would fail earlier on its required env). Either way --scala-mode parsed.
            "pc",
        ])
        .output()
        .expect("run CLI");
    let stderr = String::from_utf8_lossy(&output.stderr);
    // --scala-mode parsed as an option (guard silent), so the run reaches the determinism-flag gate.
    assert!(
        !stderr.contains("consumed as --jvm-worker argv"),
        "the terminator must stop --scala-mode being swallowed; got:\n{stderr}"
    );
    assert!(
        stderr.contains("determinism"),
        "with --scala-mode parsed, the missing determinism flags must be the failure; got:\n{stderr}"
    );
}

#[test]
#[allow(clippy::too_many_lines, reason = "linear end-to-end smoke setup")]
fn jvm_mode_fuzz_smoke_reaches_loop_without_deadlock() {
    let agent = concat!(env!("CARGO_MANIFEST_DIR"), "/../../jvm-coverage-agent/src");
    let sources = [
        format!("{agent}/cov/Cov.java"),
        format!("{agent}/cov/Lifecycle.java"),
        format!("{agent}/cov/Evidence.java"),
        format!("{agent}/cov/RunOutcome.java"),
        format!("{agent}/cov/Findings.java"),
        format!("{agent}/cov/IterationBody.java"),
        format!("{agent}/cov/FixtureBody.java"),
        format!("{agent}/cov/LsIterationBody.java"),
        format!("{agent}/cov/RunBudgetExceededException.java"),
        format!("{agent}/cov/Worker.java"),
        format!("{agent}/fixture/Target.java"),
        format!("{agent}/fixture/LateWriteFixture.java"),
        format!("{agent}/fixture/ExecutorLateWrite.java"),
    ];
    // Prove the checked-in sources exist BEFORE deciding whether the external toolchain is missing,
    // so a source-list regression fails even in a no-JDK shell. Only then may a missing javac skip.
    assert_sources_present(&sources);
    if !javac_available() {
        eprintln!("skipping: javac unavailable");
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let out = tmp.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    let compiled = Command::new("javac")
        .arg("-d")
        .arg(&out)
        .args(&sources)
        .status();
    match compiled {
        Ok(s) if s.success() => {}
        // javac is available (checked above), so a failed compile is a hard failure, not a skip.
        Ok(_) => panic!("fixture worker sources failed to compile"),
        Err(_) => {
            eprintln!("skipping: could not run javac");
            return;
        }
    }

    // Seed generation needs a grammar context, so mine a tiny Scala fragment file first (the same
    // `--language-fragments Scala=<file>` surface a real run uses). Both native and JVM modes require
    // this; it is orthogonal to the JVM-only wiring the smoke exercises.
    let src_dir = tmp.path().join("scala-src");
    std::fs::create_dir_all(&src_dir).unwrap();
    std::fs::write(
        src_dir.join("Demo.scala"),
        "object Demo:\n  def add(a: Int, b: Int): Int = a + b\n",
    )
    .unwrap();
    let frag = tmp.path().join("scala.frag");
    let mined = Command::new(env!("CARGO_BIN_EXE_lsp-fuzz-cli"))
        .args([
            "mine-code-fragments",
            "--language",
            "Scala",
            "--search-directory",
            src_dir.to_str().unwrap(),
            "--output",
            frag.to_str().unwrap(),
        ])
        .status()
        .expect("run mine-code-fragments");
    assert!(mined.success(), "mine-code-fragments failed");

    let state = tmp.path().join("state");
    // time-budget 0 stops the loop immediately after forced seed generation, which still drives the
    // worker through the executor. `--jvm-worker` argv is preserved token-for-token (no lsp target).
    let mut child = Command::new(env!("CARGO_BIN_EXE_lsp-fuzz-cli"))
        .args([
            "fuzz",
            "--state",
            state.to_str().unwrap(),
            "--language-fragments",
            &format!("Scala={}", frag.display()),
            "--time-budget",
            "0",
            "--generate-seeds",
            "2",
            // The determinism flags are required by run_jvm_mode's launch validation.
            "--jvm-worker",
            "java",
            "-XX:-UseCompactObjectHeaders",
            "-Xshare:off",
            "-XX:+UseSerialGC",
            "-cp",
            out.to_str().unwrap(),
            "cov.Worker",
        ])
        .env("RUST_LOG", "info")
        // This smoke exercises the trivial FIXTURE worker (its classpath has no language-server jar),
        // so override run_jvm_mode's default `ls` iteration body — otherwise the worker would try to
        // embed `ls.core.ScalaLs` and fail to load it.
        .env("COV_ITERATION_BODY", "fixture")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn CLI");

    // Poll for exit; a JVM-mode deadlock would otherwise hang the test.
    let deadline = Instant::now() + Duration::from_mins(2);
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("JVM-mode fuzz smoke deadlocked (did not exit within 120s)");
        }
        thread::sleep(Duration::from_millis(200));
    };
    let output = child.wait_with_output().expect("collect output");
    // The tracing logs land on stdout and the debug-build banner on stderr, so search both.
    let logs = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        logs.contains("Generating seeds"),
        "expected the JVM branch to reach seed generation; logs:\n{logs}"
    );
    // Seeds must have actually run through `JvmLspExecutor` (the JVM coverage map appears in stats).
    assert!(
        logs.contains("jvm-edges"),
        "expected seeds to execute through the JVM executor; logs:\n{logs}"
    );
    assert!(
        status.success(),
        "JVM-mode fuzz smoke exited with failure ({status}); logs:\n{logs}"
    );
}
