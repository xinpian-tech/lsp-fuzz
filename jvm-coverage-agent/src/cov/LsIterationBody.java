package cov;

import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.channels.Channels;
import java.nio.channels.Pipe;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * Real in-process language-server body: embeds {@code ls.core.ScalaLs} inside the worker JVM and
 * drives it over in-memory lsp4j streams, replicating {@code ls.core.Main}'s wiring
 * ({@code LSPLauncher} server launcher + {@code server.connect} + {@code startListening}) but with
 * NIO pipes instead of OS stdio, so the worker fully controls the per-iteration streams.
 *
 * <p>All language-server and lsp4j types are reached by reflection, so the coverage agent still
 * compiles and runs the fixture body without the language server on the compile classpath. When the
 * worker is launched with the language-server jar on its classpath and {@code COV_ITERATION_BODY=ls}
 * this body is selected; otherwise it is never constructed.
 *
 * <p>Per epoch it initializes the server once. Per input it applies the payload as a Scala document
 * (close the previous document, open the current one), issues a semantic request whose future is
 * tracked through {@link Lifecycle} so quiescence waits for it, and lets the lifecycle attribute the
 * resulting real language-server coverage. Wiring the full serialized fuzzer input (workspace +
 * message sequence) and a BSP-backed index baseline is the Scala execution profile's job; this body
 * establishes the in-process embedding and the real per-input request lifecycle it builds on.
 */
public final class LsIterationBody implements IterationBody {
    private static final long REQUEST_TIMEOUT_MS = 30_000;
    private static final String DOC_URI = "file:///lsp-fuzz/Input.scala";

    private boolean started;
    private Object textDocumentService; // lsp4j TextDocumentService proxy
    private Object serverProxy; // lsp4j LanguageServer proxy
    private int version;
    private boolean documentOpen;

    // Cached lsp4j reflection handles, resolved once the server is started.
    private Class<?> textDocumentItem;
    private Class<?> didOpenParams;
    private Class<?> didCloseParams;
    private Class<?> textDocumentIdentifier;
    private Class<?> position;
    private Class<?> hoverParams;
    private Method didOpen;
    private Method didClose;
    private Method hover;

    @Override
    public void run(byte[] payload) {
        ensureStarted();
        String text = documentText(payload);
        version++;
        try {
            if (documentOpen) {
                invoke(textDocumentService, didClose,
                        newInstance(didCloseParams, new Class<?>[] {textDocumentIdentifier},
                                newInstance(textDocumentIdentifier, new Class<?>[] {String.class}, DOC_URI)));
                documentOpen = false;
            }
            Object item = newInstance(textDocumentItem,
                    new Class<?>[] {String.class, String.class, int.class, String.class},
                    DOC_URI, "scala", version, text);
            invoke(textDocumentService, didOpen,
                    newInstance(didOpenParams, new Class<?>[] {textDocumentItem}, item));
            documentOpen = true;

            // A real semantic request; its future is tracked so quiescence waits for the server to
            // finish before the snapshot. Without a build the result may be empty/null — the point
            // is that real server code runs under this iteration's generation.
            Object id = newInstance(textDocumentIdentifier, new Class<?>[] {String.class}, DOC_URI);
            Object pos = newInstance(position, new Class<?>[] {int.class, int.class}, 0, 0);
            Object params = newInstance(hoverParams,
                    new Class<?>[] {textDocumentIdentifier, position}, id, pos);
            Object future = invoke(textDocumentService, hover, params);
            Lifecycle.track((CompletableFuture<?>) future).get(REQUEST_TIMEOUT_MS, TimeUnit.MILLISECONDS);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("in-process language-server request failed", e);
        }
    }

    /** Bring up the embedded server once per epoch: wire streams, launchers, and initialize. */
    private synchronized void ensureStarted() {
        if (started) {
            return;
        }
        try {
            ClassLoader cl = Thread.currentThread().getContextClassLoader();
            Class<?> launcher = Class.forName("org.eclipse.lsp4j.launch.LSPLauncher");
            Class<?> languageServer = Class.forName("org.eclipse.lsp4j.services.LanguageServer");
            Class<?> languageClient = Class.forName("org.eclipse.lsp4j.services.LanguageClient");

            Object server = newScalaLs();

            // Two NIO pipes: client -> server and server -> client. Real OS pipes, so lsp4j's pool
            // threads can read/write without the java.io.Piped* writer-liveness "broken pipe" trap.
            Pipe clientToServer = Pipe.open();
            Pipe serverToClient = Pipe.open();
            InputStream serverIn = Channels.newInputStream(clientToServer.source());
            OutputStream clientOut = Channels.newOutputStream(clientToServer.sink());
            InputStream clientIn = Channels.newInputStream(serverToClient.source());
            OutputStream serverOut = Channels.newOutputStream(serverToClient.sink());

            Object serverLauncher = launcher
                    .getMethod("createServerLauncher", languageServer, InputStream.class, OutputStream.class)
                    .invoke(null, server, serverIn, serverOut);
            Object clientProxy = serverLauncher.getClass().getMethod("getRemoteProxy").invoke(serverLauncher);
            server.getClass().getMethod("connect", languageClient).invoke(server, clientProxy);
            serverLauncher.getClass().getMethod("startListening").invoke(serverLauncher);

            Object localClient = Proxy.newProxyInstance(cl, new Class<?>[] {languageClient},
                    new PassiveClient());
            Object clientLauncher = launcher
                    .getMethod("createClientLauncher", languageClient, InputStream.class, OutputStream.class)
                    .invoke(null, localClient, clientIn, clientOut);
            serverProxy = clientLauncher.getClass().getMethod("getRemoteProxy").invoke(clientLauncher);
            clientLauncher.getClass().getMethod("startListening").invoke(clientLauncher);

            Class<?> initializeParams = Class.forName("org.eclipse.lsp4j.InitializeParams");
            Object init = invoke(serverProxy,
                    serverProxy.getClass().getMethod("initialize", initializeParams),
                    initializeParams.getConstructor().newInstance());
            Lifecycle.track((CompletableFuture<?>) init).get(REQUEST_TIMEOUT_MS, TimeUnit.MILLISECONDS);

            textDocumentService = serverProxy.getClass().getMethod("getTextDocumentService").invoke(serverProxy);

            textDocumentItem = Class.forName("org.eclipse.lsp4j.TextDocumentItem");
            didOpenParams = Class.forName("org.eclipse.lsp4j.DidOpenTextDocumentParams");
            didCloseParams = Class.forName("org.eclipse.lsp4j.DidCloseTextDocumentParams");
            textDocumentIdentifier = Class.forName("org.eclipse.lsp4j.TextDocumentIdentifier");
            position = Class.forName("org.eclipse.lsp4j.Position");
            hoverParams = Class.forName("org.eclipse.lsp4j.HoverParams");
            didOpen = textDocumentService.getClass().getMethod("didOpen", didOpenParams);
            didClose = textDocumentService.getClass().getMethod("didClose", didCloseParams);
            hover = textDocumentService.getClass().getMethod("hover", hoverParams);

            started = true;
        } catch (Exception e) {
            throw new RuntimeException("failed to start the in-process language server", e);
        }
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

    private static String documentText(byte[] payload) {
        if (payload == null || payload.length == 0) {
            return "object Input:\n  def value: Int = 1\n";
        }
        return new String(payload, StandardCharsets.UTF_8);
    }

    private static Object newInstance(Class<?> type, Class<?>[] sig, Object... args) throws Exception {
        return type.getConstructor(sig).newInstance(args);
    }

    private static Object invoke(Object target, Method method, Object... args) {
        try {
            return method.invoke(target, args);
        } catch (Exception e) {
            throw new RuntimeException("language-server call " + method.getName() + " failed", e);
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
