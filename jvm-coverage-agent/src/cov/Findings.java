package cov;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Per-input collector for JSON-RPC error findings observed while replaying an input. Each finding is
 * one tab-separated line {@code method\tcode\tmessage} published to {@code $COV_FINDINGS_PATH} (when
 * set) so the Rust driver can read them into its deduplicated finding set. The collector is reset at
 * the start of every input and published at the end, mirroring the completed-requests side channel.
 */
public final class Findings {
    private final List<String> lines = new ArrayList<>();

    /** Clear the collected findings at the start of an input. */
    void reset() {
        lines.clear();
    }

    /** Record one JSON-RPC error response as a finding (tabs/newlines in the message are flattened). */
    void recordJsonRpcError(String method, long code, String message) {
        String safeMethod = flatten(method);
        String safeMessage = flatten(message);
        lines.add(safeMethod + "\t" + code + "\t" + safeMessage);
    }

    /** Publish the collected findings to {@code $COV_FINDINGS_PATH}, if that env var is set. */
    void publish() {
        String path = System.getenv("COV_FINDINGS_PATH");
        if (path == null) {
            return;
        }
        try {
            Files.write(Path.of(path), lines);
        } catch (IOException e) {
            throw new RuntimeException("failed to write " + path, e);
        }
    }

    private static String flatten(String s) {
        if (s == null) {
            return "";
        }
        return s.replace('\t', ' ').replace('\r', ' ').replace('\n', ' ');
    }
}
