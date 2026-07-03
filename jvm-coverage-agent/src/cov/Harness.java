package cov;

import java.io.DataInputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Coverage worker harness: drives the persistent {@link WorkerHandle} over its control protocol and
 * asserts the full property set — saturation, non-empty/deterministic/input-sensitive coverage, a
 * large transport payload, a 1000-identical-input stability gate with bounded thread/fd growth,
 * outcome classification with timeout kill + epoch restart, and saved-input cold replay. Not
 * instrumented. Exit code 0 iff every gate passes.
 */
public final class Harness {
    private static final int MAP_SIZE = Cov.MAP_SIZE;
    private static final long HEAP_CEILING_BYTES = 512L * 1024 * 1024;
    private static final int THREAD_TOLERANCE = 3;
    private static final int FD_TOLERANCE = 8;
    private static final String[] JVM_FLAGS = {
        "-XX:-UseCompactObjectHeaders",
        "-Xshare:off",
        "-XX:+UseSerialGC",
        "--enable-native-access=ALL-UNNAMED",
    };

    private int failures = 0;

    public static void main(String[] args) throws Exception {
        Harness h = new Harness();
        h.saturationGate();
        h.classReachOracleGate();
        WorkerHandle w = new WorkerHandle();
        try {
            h.coverageGates(w);
            h.transportGate(w);
            h.stabilityGate(w);
            h.classificationAndRestartGates(w);
        } finally {
            w.close();
        }
        h.coldReplayGate();
        System.exit(h.failures == 0 ? 0 : 1);
    }

    private void ok(String msg) {
        System.out.println("OK: " + msg);
    }

    private void fail(String msg) {
        System.out.println("FAIL: " + msg);
        failures++;
    }

    /** Saturating counters: hitting one edge >255 times must leave 0xff, never wrap to 0. */
    private void saturationGate() {
        Cov.reset();
        for (int i = 0; i < 300; i++) {
            Cov.hit(0); // prev stays 0, so edge 0 is incremented every call
        }
        int v = Cov.MAP[0] & 0xff;
        if (v == 0xff) {
            ok("counter saturates at 0xff after 300 hits");
        } else {
            fail("counter did not saturate (edge 0 = " + v + " after 300 hits)");
        }
        Cov.reset();
    }

    /**
     * Covered-class tracking must be collision-free: two classes whose 16-bit edge-hash id
     * collides must still be reported by name. Uses unique sequential ids (as the agent does), so
     * the edge-hash collision cannot misattribute package reach.
     */
    private void classReachOracleGate() {
        // Brute-force a pair of distinct names that share the same 16-bit edge-hash id.
        String a = null;
        String b = null;
        Map<Integer, String> seen = new HashMap<>();
        for (int i = 0; a == null && i < 1_000_000; i++) {
            String name = "pkg.C" + i;
            int id = CoverageAgent.stableId(name);
            String prev = seen.putIfAbsent(id, name);
            if (prev != null) {
                a = prev;
                b = name;
            }
        }
        if (a == null || CoverageAgent.stableId(a) != CoverageAgent.stableId(b)) {
            fail("class-reach oracle test could not construct a colliding pair");
            return;
        }
        Cov.reset();
        Cov.registerClass(0, a); // unique sequential ids, unlike the 16-bit edge hash
        Cov.registerClass(1, b);
        Cov.cls(0);
        Cov.cls(1);
        List<String> names = Cov.coveredClassNames();
        if (names.contains(a) && names.contains(b)) {
            ok("class-reach oracle is collision-free (edge-hash-colliding " + a + "/" + b
                    + " both reported)");
        } else {
            fail("class-reach oracle dropped a colliding class: " + names);
        }
        Cov.reset();
    }

    private void coverageGates(WorkerHandle w) throws Exception {
        Run a1 = w.run("abc".getBytes(), 5000);
        Run a2 = w.run("abc".getBytes(), 5000);
        Run b = w.run("z".getBytes(), 5000);
        if (a1 == null || a2 == null || b == null) {
            fail("coverage gate: unexpected timeout");
            return;
        }
        int nz = countNonZero(a1.map);
        if (nz > 0) {
            ok("basic-block coverage non-empty (" + nz + " edges)");
        } else {
            fail("coverage map empty");
        }
        if (Arrays.equals(a1.map, a2.map)) {
            ok("deterministic (identical input -> identical map)");
        } else {
            fail("identical input produced different maps");
        }
        if (!Arrays.equals(a1.map, b.map)) {
            ok("input-sensitive (different input -> different map)");
        } else {
            fail("different input produced identical map");
        }
    }

    /** LSPFuzz-sized transport: a large deterministic payload runs and is stable. */
    private void transportGate(WorkerHandle w) throws Exception {
        byte[] big = new byte[256 * 1024];
        for (int i = 0; i < big.length; i++) {
            big[i] = (byte) ((i % 251) + 1); // never 0x00/0xEE/0xFF at index 0
        }
        Run r1 = w.run(big, 10000);
        Run r2 = w.run(big, 10000);
        if (r1 != null && r2 != null && r1.outcome == 0 && countNonZero(r1.map) > 0
                && Arrays.equals(r1.map, r2.map)) {
            ok("transport: 256 KiB payload -> OK, non-empty, byte-identical maps");
        } else {
            fail("transport gate failed for 256 KiB payload");
        }
    }

    /** 1000 runs of the same input in one persistent JVM: identical maps + bounded resources. */
    private void stabilityGate(WorkerHandle w) throws Exception {
        byte[] input = "stability-probe".getBytes();
        Status before = w.status(5000);
        Run first = w.run(input, 5000);
        if (before == null || first == null) {
            fail("stability gate: setup timed out");
            return;
        }
        for (int i = 1; i < 1000; i++) {
            Run r = w.run(input, 5000);
            if (r == null || !Arrays.equals(first.map, r.map)) {
                fail("stability gate diverged at iteration " + i);
                return;
            }
        }
        Status after = w.status(5000);
        if (after == null || !w.process.isAlive()) {
            fail("stability gate: worker not responsive after loop");
            return;
        }
        int threadGrowth = after.threads - before.threads;
        long fdGrowth = after.fds - before.fds;
        boolean bounded = threadGrowth <= THREAD_TOLERANCE
                && fdGrowth <= FD_TOLERANCE
                && after.usedHeap < HEAP_CEILING_BYTES;
        String detail = "threads " + before.threads + "->" + after.threads
                + ", fds " + before.fds + "->" + after.fds
                + ", heap " + (after.usedHeap / (1024 * 1024)) + "MiB";
        if (bounded) {
            ok("1000-identical-input stability: byte-identical maps; bounded resources (" + detail + ")");
        } else {
            fail("stability gate: resource growth out of tolerance (" + detail + ")");
        }
    }

    /** Classification + the actual timeout-kill-then-epoch-restart proof. */
    private void classificationAndRestartGates(WorkerHandle w) throws Exception {
        Run normal = w.run("hello".getBytes(), 5000);
        if (normal != null && normal.outcome == 0) {
            ok("normal input classified OK");
        } else {
            fail("normal input misclassified");
        }
        Run crash = w.run(new byte[] {(byte) 0xEE}, 5000);
        if (crash != null && crash.outcome == 1) {
            ok("uncaught exception classified CRASH");
        } else {
            fail("crash input not classified as CRASH");
        }
        // Hang -> no response within timeout -> the worker is force-killed.
        Run hang = w.run(new byte[] {(byte) 0xFF}, 1500);
        if (hang != null) {
            fail("hang input unexpectedly returned outcome " + hang.outcome);
            return;
        }
        w.process.waitFor(2, TimeUnit.SECONDS);
        if (w.process.isAlive()) {
            fail("hung worker was not killed");
            return;
        }
        ok("hang input timed out and the worker was killed");
        // Epoch restart: a fresh worker must serve a normal input with real coverage.
        WorkerHandle restarted = new WorkerHandle();
        try {
            Run afterRestart = restarted.run("post-restart".getBytes(), 5000);
            if (afterRestart != null && afterRestart.outcome == 0 && countNonZero(afterRestart.map) > 0) {
                ok("epoch restart: fresh worker serves a normal input after the kill");
            } else {
                fail("epoch restart: fresh worker did not serve a normal input");
            }
        } finally {
            restarted.close();
        }
    }

    /** Cold replay from a saved input file: reproduces the same outcome class from a fresh JVM. */
    private void coldReplayGate() throws Exception {
        Path replayFile = Path.of("replay-input.bin");
        Files.write(replayFile, new byte[] {(byte) 0xEE}); // saved crash artifact
        byte[] saved = Files.readAllBytes(replayFile);
        WorkerHandle fresh = new WorkerHandle();
        try {
            Run replay = fresh.run(saved, 5000);
            if (replay != null && replay.outcome == 1 && countNonZero(replay.map) > 0) {
                ok("cold replay: saved crash input reproduced from a fresh JVM worker");
            } else {
                fail("cold replay did not reproduce the crash");
            }
        } finally {
            fresh.close();
            Files.deleteIfExists(replayFile);
        }
    }

    private static int countNonZero(byte[] map) {
        int n = 0;
        for (byte b : map) {
            if (b != 0) {
                n++;
            }
        }
        return n;
    }

    private record Run(int outcome, byte[] map) {}

    private record Status(long usedHeap, int threads, long fds) {}

    /** Spawns and talks to the agent-instrumented worker JVM. */
    private static final class WorkerHandle implements AutoCloseable {
        final Process process;
        private final OutputStream toWorker;
        private final DataInputStream fromWorker;
        private final ExecutorService reader = Executors.newSingleThreadExecutor();

        WorkerHandle() throws Exception {
            String java = System.getProperty("java.home") + "/bin/java";
            List<String> cmd = new ArrayList<>();
            cmd.add(java);
            cmd.addAll(Arrays.asList(JVM_FLAGS));
            cmd.add("-javaagent:agent.jar");
            cmd.add("-cp");
            cmd.add("out");
            cmd.add("cov.Worker");
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.environment().put("COV_MAP_PATH", "map-latest.bin");
            pb.redirectError(ProcessBuilder.Redirect.INHERIT);
            this.process = pb.start();
            this.toWorker = process.getOutputStream();
            this.fromWorker = new DataInputStream(process.getInputStream());
        }

        Run run(byte[] input, long timeoutMs) throws Exception {
            toWorker.write('R');
            toWorker.write((input.length >>> 24) & 0xff);
            toWorker.write((input.length >>> 16) & 0xff);
            toWorker.write((input.length >>> 8) & 0xff);
            toWorker.write(input.length & 0xff);
            toWorker.write(input);
            toWorker.flush();
            return await(() -> {
                int outcome = fromWorker.readUnsignedByte();
                byte[] map = new byte[MAP_SIZE];
                fromWorker.readFully(map);
                return new Run(outcome, map);
            }, timeoutMs);
        }

        Status status(long timeoutMs) throws Exception {
            toWorker.write('S');
            toWorker.flush();
            return await(() -> new Status(fromWorker.readLong(), fromWorker.readInt(),
                    fromWorker.readLong()), timeoutMs);
        }

        private <T> T await(Callable<T> read, long timeoutMs) throws Exception {
            Future<T> f = reader.submit(read);
            try {
                return f.get(timeoutMs, TimeUnit.MILLISECONDS);
            } catch (TimeoutException e) {
                f.cancel(true);
                process.destroyForcibly(); // kill the hung epoch
                return null;
            }
        }

        @Override
        public void close() {
            try {
                if (process.isAlive()) {
                    toWorker.write('Q');
                    toWorker.flush();
                    process.waitFor(2, TimeUnit.SECONDS);
                }
            } catch (Exception ignored) {
                // fall through to force kill
            }
            process.destroyForcibly();
            reader.shutdownNow();
        }
    }
}
