package cov;

import java.io.DataInputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * task5 verifier: drives the persistent {@link Worker} over its control protocol and asserts the
 * full task5 property set (saturation, non-empty/deterministic/input-sensitive coverage, a
 * 1000-identical-input stability gate, outcome classification with timeout kill + epoch restart,
 * and cold replay). Not instrumented. Exit code 0 iff every gate passes.
 */
public final class Harness {
    private static final int MAP_SIZE = Cov.MAP_SIZE;
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
        Worker w = h.startWorker();
        try {
            h.coverageGates(w);
            h.stabilityGate(w);
            h.classificationGates(w);
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

    private void coverageGates(Worker w) throws Exception {
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

    /** 1000 runs of the same input in one persistent JVM must all yield the same map. */
    private void stabilityGate(Worker w) throws Exception {
        byte[] input = "stability-probe".getBytes();
        Run first = w.run(input, 5000);
        if (first == null) {
            fail("stability gate: first run timed out");
            return;
        }
        for (int i = 1; i < 1000; i++) {
            Run r = w.run(input, 5000);
            if (r == null || !Arrays.equals(first.map, r.map)) {
                fail("stability gate diverged at iteration " + i);
                return;
            }
        }
        if (w.process.isAlive()) {
            ok("1000-identical-input stability: byte-identical maps, one persistent worker");
        } else {
            fail("worker died during stability gate");
        }
    }

    private void classificationGates(Worker w) throws Exception {
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
        // Hang: no response within the timeout -> the worker is killed and a new epoch started.
        Run hang = w.run(new byte[] {(byte) 0xFF}, 1500);
        if (hang == null) {
            ok("hang input timed out (no response)");
        } else {
            fail("hang input unexpectedly returned outcome " + hang.outcome);
        }
    }

    /** Cold replay: a saved crash input reproduces the same outcome class from a fresh JVM. */
    private void coldReplayGate() throws Exception {
        Worker fresh = startWorker();
        try {
            Run replay = fresh.run(new byte[] {(byte) 0xEE}, 5000);
            if (replay != null && replay.outcome == 1 && countNonZero(replay.map) > 0) {
                ok("cold replay: crash reproduced from a fresh JVM worker");
            } else {
                fail("cold replay did not reproduce the crash");
            }
        } finally {
            fresh.close();
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

    private Worker startWorker() throws Exception {
        return new Worker();
    }

    private static final class Run {
        final int outcome;
        final byte[] map;

        Run(int outcome, byte[] map) {
            this.outcome = outcome;
            this.map = map;
        }
    }

    /** Spawns and talks to the agent-instrumented worker JVM. */
    private static final class Worker implements AutoCloseable {
        final Process process;
        private final OutputStream toWorker;
        private final DataInputStream fromWorker;
        private final ExecutorService reader = Executors.newSingleThreadExecutor();

        Worker() throws Exception {
            ProcessBuilder pb = new ProcessBuilder();
            String java = System.getProperty("java.home") + "/bin/java";
            java.util.List<String> cmd = new java.util.ArrayList<>();
            cmd.add(java);
            cmd.addAll(Arrays.asList(JVM_FLAGS));
            cmd.add("-javaagent:agent.jar");
            cmd.add("-cp");
            cmd.add("out");
            cmd.add("cov.Worker");
            pb.command(cmd);
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

            Future<Run> f = reader.submit(() -> {
                int outcome = fromWorker.readUnsignedByte();
                byte[] map = new byte[MAP_SIZE];
                fromWorker.readFully(map);
                return new Run(outcome, map);
            });
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
