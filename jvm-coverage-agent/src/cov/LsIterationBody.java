package cov;

import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.channels.Channels;
import java.nio.channels.Pipe;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Real in-process language-server body: embeds {@code ls.core.ScalaLs} inside the worker JVM and
 * drives it over in-memory lsp4j streams, replicating {@code ls.core.Main}'s wiring but with NIO
 * pipes (java.io.Piped* throws "broken pipe" under lsp4j's pool threads). All language-server and
 * lsp4j types are reached by reflection so the agent still builds and runs the fixture body without
 * the server on the compile classpath. Selected by {@code COV_ITERATION_BODY=ls}.
 *
 * <p>Each run receives the JVM worker envelope
 * ({@code <u32le rootUriLen><rootUri><localized framed JSON-RPC stream>}) built by
 * {@code JvmLspInputConverter}: the real fuzzer input, workspace-materialized and URI-localized.
 * This body parses the framed stream and replays the input's actual messages through lsp4j's
 * low-level {@code RemoteEndpoint}. The server lifecycle is owned per epoch: {@code
 * initialize}/{@code initialized} are forwarded once, {@code shutdown}/{@code exit} are skipped. Per
 * input it closes the documents opened by the previous input, opens the current input's documents,
 * forwards every stored request (tracked through {@link Lifecycle} so quiescence drains it) and
 * notification (untracked). Mutating the input's messages or workspace therefore changes exactly
 * what the real server executes.
 */
public final class LsIterationBody implements IterationBody {
    private static final long REQUEST_TIMEOUT_MS = 30_000;

    private boolean started;
    private boolean initializeSent;
    private boolean initializedSent;
    private Object endpoint; // org.eclipse.lsp4j.jsonrpc.RemoteEndpoint (implements Endpoint)
    private final List<String> openDocuments = new ArrayList<>();

    // Cached reflection handles.
    private Method endpointRequest; // Endpoint.request(String, Object) -> CompletableFuture
    private Method endpointNotify; // Endpoint.notify(String, Object)
    private Method jsonParse; // JsonParser.parseString(String) -> JsonElement
    private Method asJsonObject; // JsonElement.getAsJsonObject()
    private Method objHas; // JsonObject.has(String)
    private Method objGet; // JsonObject.get(String) -> JsonElement
    private Method elemAsString; // JsonElement.getAsString()

    @Override
    public void run(byte[] payload) {
        ensureStarted();
        Envelope env = Envelope.parse(payload);
        try {
            // Per-input document reset: close everything the previous input opened.
            for (String uri : openDocuments) {
                notifyServer("textDocument/didClose",
                        json("{\"textDocument\":{\"uri\":" + quote(uri) + "}}"));
            }
            openDocuments.clear();

            for (byte[] frame : env.frames) {
                dispatch(new String(frame, StandardCharsets.UTF_8));
            }
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("replaying the input's LSP sequence failed", e);
        }
    }

    /** Forward one JSON-RPC frame, owning the server lifecycle and tracking request futures. */
    private void dispatch(String body) throws Exception {
        Object obj = asJsonObject.invoke(jsonParse.invoke(null, body));
        String method = optString(obj, "method");
        if (method == null) {
            return; // a response echoed into the stream (there are none here): ignore
        }
        Object params = has(obj, "params") ? get(obj, "params") : null;
        boolean isRequest = has(obj, "id");

        switch (method) {
            case "initialize" -> {
                if (!initializeSent) {
                    requestAndWait(method, params);
                    initializeSent = true;
                }
            }
            case "initialized" -> {
                if (!initializedSent) {
                    notifyServer(method, params);
                    initializedSent = true;
                }
            }
            case "shutdown", "exit" -> {
                // Owned by epoch teardown, never per input — the worker reuses this server.
            }
            case "textDocument/didOpen" -> {
                notifyServer(method, params);
                String uri = documentUri(params);
                if (uri != null) {
                    openDocuments.add(uri);
                }
            }
            default -> {
                if (isRequest) {
                    requestAndWait(method, params);
                } else {
                    notifyServer(method, params);
                }
            }
        }
    }

    private void requestAndWait(String method, Object params) throws Exception {
        Object future = endpointRequest.invoke(endpoint, method, params);
        Lifecycle.track((CompletableFuture<?>) future).get(REQUEST_TIMEOUT_MS, TimeUnit.MILLISECONDS);
    }

    private void notifyServer(String method, Object params) throws Exception {
        endpointNotify.invoke(endpoint, method, params);
    }

    /** Bring up the embedded server once per epoch: wire streams, launchers, and reflection. */
    private synchronized void ensureStarted() {
        if (started) {
            return;
        }
        try {
            Class<?> launcherBuilder = Class.forName("org.eclipse.lsp4j.launch.LSPLauncher$Builder");
            Class<?> languageServer = Class.forName("org.eclipse.lsp4j.services.LanguageServer");
            Class<?> languageClient = Class.forName("org.eclipse.lsp4j.services.LanguageClient");
            Class<?> endpointCls = Class.forName("org.eclipse.lsp4j.jsonrpc.Endpoint");

            Object server = newScalaLs();

            // Real OS pipes: java.io.Piped* trips a "broken pipe" on lsp4j's pool-thread writes.
            Pipe clientToServer = Pipe.open();
            Pipe serverToClient = Pipe.open();
            InputStream serverIn = Channels.newInputStream(clientToServer.source());
            OutputStream clientOut = Channels.newOutputStream(clientToServer.sink());
            InputStream clientIn = Channels.newInputStream(serverToClient.source());
            OutputStream serverOut = Channels.newOutputStream(serverToClient.sink());

            // lsp4j serves every input on one long-lived read-loop thread, so that thread must write
            // under whatever generation is currently active — it cannot carry a single captured
            // generation without suppressing later inputs' coverage. Cross-input safety instead comes
            // from tracking each request future so quiescence drains the server's work within the
            // input, plus the snapshot/late-watch/pre-reset guards. Detached generation-scoped
            // background executors belong to the BSP/index profile (task-level follow-up).
            ExecutorService exec = Executors.newCachedThreadPool(r -> {
                Thread t = new Thread(r, "lsp-fuzz-ls");
                t.setDaemon(true);
                return t;
            });

            Object serverLauncher = buildLauncher(launcherBuilder, server, languageClient,
                    serverIn, serverOut, exec);
            Object clientProxy = serverLauncher.getClass().getMethod("getRemoteProxy")
                    .invoke(serverLauncher);
            server.getClass().getMethod("connect", languageClient).invoke(server, clientProxy);
            serverLauncher.getClass().getMethod("startListening").invoke(serverLauncher);

            Object passiveClient = Proxy.newProxyInstance(
                    Thread.currentThread().getContextClassLoader(),
                    new Class<?>[] {languageClient}, new PassiveClient());
            Object clientLauncher = buildLauncher(launcherBuilder, passiveClient, languageServer,
                    clientIn, clientOut, exec);
            clientLauncher.getClass().getMethod("startListening").invoke(clientLauncher);
            endpoint = clientLauncher.getClass().getMethod("getRemoteEndpoint").invoke(clientLauncher);

            endpointRequest = endpointCls.getMethod("request", String.class, Object.class);
            endpointNotify = endpointCls.getMethod("notify", String.class, Object.class);

            Class<?> jsonParser = Class.forName("com.google.gson.JsonParser");
            Class<?> jsonElement = Class.forName("com.google.gson.JsonElement");
            Class<?> jsonObject = Class.forName("com.google.gson.JsonObject");
            jsonParse = jsonParser.getMethod("parseString", String.class);
            asJsonObject = jsonElement.getMethod("getAsJsonObject");
            objHas = jsonObject.getMethod("has", String.class);
            objGet = jsonObject.getMethod("get", String.class);
            elemAsString = jsonElement.getMethod("getAsString");

            started = true;
        } catch (Exception e) {
            throw new RuntimeException("failed to start the in-process language server", e);
        }
    }

    private static Object buildLauncher(Class<?> builderCls, Object localService, Class<?> remote,
            InputStream in, OutputStream out, ExecutorService exec) throws Exception {
        Object b = builderCls.getConstructor().newInstance();
        builderCls.getMethod("setLocalService", Object.class).invoke(b, localService);
        builderCls.getMethod("setRemoteInterface", Class.class).invoke(b, remote);
        builderCls.getMethod("setInput", InputStream.class).invoke(b, in);
        builderCls.getMethod("setOutput", OutputStream.class).invoke(b, out);
        builderCls.getMethod("setExecutorService", ExecutorService.class).invoke(b, exec);
        return builderCls.getMethod("create").invoke(b);
    }

    /** Construct {@code new ScalaLs(ScalaLs.Config())} reflectively (the primary-ctor default). */
    private static Object newScalaLs() throws Exception {
        Class<?> scalaLs = Class.forName("ls.core.ScalaLs");
        Class<?> companion = Class.forName("ls.core.ScalaLs$");
        Class<?> config = Class.forName("ls.core.ScalaLs$Config");
        Object module = companion.getField("MODULE$").get(null);
        Object defaultConfig = companion.getMethod("$lessinit$greater$default$1").invoke(module);
        return scalaLs.getConstructor(config).newInstance(defaultConfig);
    }

    private Object json(String text) throws Exception {
        return jsonParse.invoke(null, text);
    }

    private boolean has(Object obj, String key) throws Exception {
        return (Boolean) objHas.invoke(obj, key);
    }

    private Object get(Object obj, String key) throws Exception {
        return objGet.invoke(obj, key);
    }

    private String optString(Object obj, String key) throws Exception {
        return has(obj, key) ? (String) elemAsString.invoke(get(obj, key)) : null;
    }

    /** Extract `params.textDocument.uri` from a didOpen params element, or null. */
    private String documentUri(Object params) {
        try {
            Object paramsObj = asJsonObject.invoke(params);
            Object textDoc = asJsonObject.invoke(get(paramsObj, "textDocument"));
            return (String) elemAsString.invoke(get(textDoc, "uri"));
        } catch (Exception e) {
            return null;
        }
    }

    private static String quote(String s) {
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '"' || c == '\\') {
                sb.append('\\');
            }
            sb.append(c);
        }
        return sb.append('"').toString();
    }

    /** The worker envelope: a localized workspace root plus the framed JSON-RPC message stream. */
    private record Envelope(String rootUri, List<byte[]> frames) {
        static Envelope parse(byte[] payload) {
            int rootLen = (payload[0] & 0xff) | (payload[1] & 0xff) << 8
                    | (payload[2] & 0xff) << 16 | (payload[3] & 0xff) << 24;
            String rootUri = new String(payload, 4, rootLen, StandardCharsets.UTF_8);
            int pos = 4 + rootLen;
            List<byte[]> frames = new ArrayList<>();
            while (pos < payload.length) {
                int headerEnd = indexOf(payload, pos);
                if (headerEnd < 0) {
                    break;
                }
                String headers = new String(payload, pos, headerEnd - pos, StandardCharsets.ISO_8859_1);
                int len = contentLength(headers);
                int bodyStart = headerEnd + 4;
                if (len < 0 || bodyStart + len > payload.length) {
                    break;
                }
                byte[] body = new byte[len];
                System.arraycopy(payload, bodyStart, body, 0, len);
                frames.add(body);
                pos = bodyStart + len;
            }
            return new Envelope(rootUri, frames);
        }

        private static int indexOf(byte[] data, int from) {
            for (int i = from; i + 3 < data.length; i++) {
                if (data[i] == '\r' && data[i + 1] == '\n' && data[i + 2] == '\r'
                        && data[i + 3] == '\n') {
                    return i;
                }
            }
            return -1;
        }

        private static int contentLength(String headers) {
            for (String line : headers.split("\r\n")) {
                int colon = line.indexOf(':');
                if (colon > 0 && line.substring(0, colon).trim().equalsIgnoreCase("Content-Length")) {
                    try {
                        return Integer.parseInt(line.substring(colon + 1).trim());
                    } catch (NumberFormatException e) {
                        return -1;
                    }
                }
            }
            return -1;
        }
    }

    /** Minimal client: complete every request with null and ignore every notification. */
    private static final class PassiveClient implements InvocationHandler {
        @Override
        public Object invoke(Object proxy, Method method, Object[] args) {
            if (CompletableFuture.class.isAssignableFrom(method.getReturnType())) {
                return CompletableFuture.completedFuture(null);
            }
            if ("toString".equals(method.getName())) {
                return "lsp-fuzz-passive-client";
            }
            return null;
        }
    }
}
