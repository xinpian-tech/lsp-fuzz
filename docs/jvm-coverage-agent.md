# JVM bytecode-coverage agent decision (plan task4)

Pins the coverage-agent choice, instrumentation scope, coverage-map shape, and determinism
settings that the JVM coverage bridge (task5–task8) builds on. Target: `scala3-bsp-smantic-ls`
(`ls.core.Main`), Java 25 + Scala 3.8.4. Architecture is Option B (`rlcr.md` DEC-1): the agent is
the **coverage source only**; its map is read by a new JVM-specific LibAFL executor — the agent is
**not** an AFL fork-server.

> Routing note: task4 is an `analyze` task. The `/humanize:ask-codex` route was attempted but the
> high-effort Codex run exceeded the 10-minute tool budget without producing output; this decision
> was authored directly and should be re-validated by Codex when a longer-running route is
> available. It is intentionally reversible — nothing downstream hard-codes the agent brand beyond
> the coverage-map contract in §3.

## 1. DECISION
Use a **custom `java.lang.instrument` + ASM `ClassFileTransformer` agent** (Kelinci-style), pinned
to **ASM 9.8** — the first ASM release with explicit Java 24/25 support (class-file major 69 /
`Opcodes.V25`); the transformer uses the `Opcodes.ASM9` API level. (ASM 9.7 / 9.7.1 only reach
Java 23 and reject major-69 classes, so the `>= 9.7` lower bound from the first draft is wrong for
JDK 25.) Not Jazzer, not JaCoCo:

- **Jazzer** is libFuzzer-oriented; its coverage is bound to its own driver/`CoverageMap`, and its
  JDK support historically lags new releases (JDK 25 is brand new). Reusing it purely as a
  coverage source feeding our Rust executor couples us to Jazzer internals for little gain.
- **JaCoCo** emits line/branch coverage for *reporting*, written to `.exec` files — the wrong shape
  (not AFL 8-bit edge counters in shared memory) and its class-file-version support also lags.
- A **custom ASM agent** (a few hundred lines) gives exact control: instrument at class-load, emit
  AFL-style edge counters into a shared memory-mapped byte array, and scope instrumentation by
  package. ASM adopts new class-file versions fastest, which is the decisive constraint on JDK 25.

## 2. INSTRUMENTATION_SCOPE
Instrument (the crash-rich surface):
- `ls.` — the language server's own code.
- `dotty.tools.` — the Scala 3 presentation compiler (completion/hover/definition).
- `scala.meta.` — scalameta / SemanticDB parsing.
- `org.eclipse.lsp4j.`, `ch.epfl.scala.` (bsp4j) — the Java protocol layers.

Exclude (noise / init / hot runtime that would saturate the map):
- `java.`, `javax.`, `jdk.`, `sun.`, `com.sun.`, `scala.runtime.`, `scala.collection.` core,
  `coursier.`, `mill.`, and the agent's own classes.
- Do not instrument FFM downcall stubs.

Measure map collision by the non-zero fill ratio after a warmup run; if fill approaches saturation,
tighten excludes or raise `MAP_SIZE` (§3).

## 3. COVERAGE_MAP (the contract the Rust executor depends on)
- `MAP_SIZE = 2^16` (65536), AFL default; 8-bit **saturating** counters.
- Edge scheme: each basic block gets a **deterministic** id (this is a runtime
  `ClassFileTransformer`, not AFL compile-time instrumentation, so ids must NOT come from load
  order or a runtime RNG or the map would differ across JVM epochs and break AC-2 stability and
  AC-5 cold-replay/provenance). Derive `blockId = truncate16(stableHash(className + "#" +
  methodName + methodDescriptor + "@" + basicBlockOrdinal, AGENT_SEED))` where `AGENT_SEED` is a
  fixed, versioned constant baked into the agent. On each edge
  `counters[(prev ^ cur) & (MAP_SIZE-1)] += 1` (saturating), with `prev = cur >> 1`. Because the
  hash inputs are stable per class/method, the same code always instruments to the same ids on
  every JVM launch, so identical inputs produce byte-identical maps and cold replay reproduces.
- Exposed to Rust as a **memory-mapped file** whose path is passed to the JVM worker by the
  executor via an env var; both sides `mmap` it. (A `MemorySegment` over the same file on the JVM
  side; a plain shared slice on the Rust side — this is the executor's `Observer` map in task8.)
- Thread-safety: background PC/BSP threads also increment; use plain racy increments, exactly as
  AFL does — coverage is approximate and races are acceptable. Per-iteration attribution is the
  executor's job (reset → run → quiesce → copy; task7/AC-3.1), not the agent's.

## 4. DETERMINISM_FLAGS (DEC-3; for the fuzzing config)
- `-XX:-UseCompactObjectHeaders` — disable compact object headers.
- Do not enable the AOT cache: omit `-XX:AOTCache`/`-XX:AOTCacheOutput`; `-Xshare:off` to disable
  CDS as well.
- `-XX:+UseSerialGC` — one GC thread, less GC-thread coverage noise.
- Start with the JIT on for throughput; if the 1000-identical-input stability gate (AC-2) fails,
  step down to `-XX:TieredStopAtLevel=1` (and `-Xint` only as a last resort — large speed cost).
- `--enable-native-access=ALL-UNNAMED` (the target already needs it for FFM).

## 5. RISKS_AND_FALLBACK
- **JDK 25 newness** is the top risk: confirm the pinned ASM handles class-file major 69, and that
  `java.lang.instrument` retransformation works under the JDK 25 module system (may need
  `--add-opens`/`--enable-native-access`). Verify on the `.#jvm` shell before task5.
- If the custom agent hits a JDK 25 blocker, fallbacks in order: (a) Jazzer's instrumentor used as
  a library if it has added JDK 25 support; (b) JaCoCo offline instrumentation as a coarse,
  lower-fidelity stopgap while the custom agent is fixed.
- Map saturation from over-broad instrumentation → tighten §2 excludes or raise `MAP_SIZE` to 2^18.

## Next (task5)
Build a trivial instrumented JVM worker/fixture and prove: non-empty stable AFL-shaped coverage,
LSPFuzz-sized input transport, crash classification, timeout kill/restart, bounded resources, and
1000-identical-input coverage stability — then task6 runs it on the real `ls.core.Main`.
