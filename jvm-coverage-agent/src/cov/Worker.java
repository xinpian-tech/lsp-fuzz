package cov;

import java.io.DataInputStream;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;

import fixture.Target;

/**
 * Persistent JVM worker — the JVM half of the Option-B bridge (the Rust LibAFL executor is task7/8).
 * It loops over a tiny binary control protocol on stdio so the same warmed, agent-instrumented JVM
 * serves many inputs without restart:
 *
 * <pre>
 *   request  : 'R' u32be(len) bytes[len]     run one input
 *            | 'Q'                            quit
 *   response : u8 outcome  bytes[MAP_SIZE]    outcome + coverage snapshot
 * </pre>
 *
 * outcome: 0 = OK, 1 = CRASH (uncaught Throwable). A hang never responds; the driver enforces the
 * timeout by killing this process and starting a new epoch. Each request resets the map first, so
 * the returned coverage is attributable to that input.
 */
public final class Worker {
    private static final int OK = 0;
    private static final int CRASH = 1;

    private Worker() {}

    public static void main(String[] args) throws Exception {
        DataInputStream in = new DataInputStream(new FileInputStream(FileDescriptor.in));
        OutputStream out = new FileOutputStream(FileDescriptor.out);
        while (true) {
            int op = in.read();
            if (op < 0 || op == 'Q') {
                break;
            }
            if (op != 'R') {
                continue;
            }
            int len = in.readInt();
            byte[] payload = in.readNBytes(len);

            Cov.reset();
            int outcome;
            try {
                Target.run(payload); // may hang (0xFF) -> no response; driver times out
                outcome = OK;
            } catch (Throwable t) {
                outcome = CRASH;
            }
            Cov.dump(); // cold-replay provenance

            out.write(outcome);
            out.write(Cov.MAP);
            out.flush();
        }
    }
}
