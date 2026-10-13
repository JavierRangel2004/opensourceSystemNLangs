package edu.up.wazuh.app;

import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import edu.up.wazuh.events.AlertParser;
import edu.up.wazuh.model.Alert;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Servidor HTTP loopback que recibe webhooks de Wazuh.
 *
 * <ul>
 *   <li>{@code POST /api/wazuh-events} con cabecera {@code Authorization: Bearer <WEBHOOK_TOKEN>}.</li>
 *   <li>Cuerpo máximo 1 MiB; payloads mayores -> 413.</li>
 *   <li>Métodos distintos de POST/OPTIONS -> 405.</li>
 *   <li>Cabecera de autorización ausente o incorrecta -> 401.</li>
 *   <li>JSON inválido -> 400.</li>
 *   <li>Ingesta delegada a un pool acotado (no bloquea el hilo HTTP).</li>
 * </ul>
 */
public final class WebHookServer implements AutoCloseable {

    private final HttpServer server;
    private final ExecutorService httpExecutor;
    private final TokenStore tokens;
    private final IngestionCoordinator coordinator;
    private final AlertParser parser = new AlertParser();
    private final int maxBodyBytes;
    private final AtomicLong accepted = new AtomicLong();
    private final AtomicLong malformed = new AtomicLong();
    private final AtomicLong unauthorized = new AtomicLong();
    private final AtomicLong oversized = new AtomicLong();
    private final AtomicLong methodNotAllowed = new AtomicLong();
    private final AtomicLong dropped = new AtomicLong();

    public WebHookServer(String host, int port, TokenStore tokens,
                         IngestionCoordinator coordinator) throws IOException {
        this(host, port, tokens, coordinator, AppConfig.MAX_BODY_BYTES);
    }

    public WebHookServer(String host, int port, TokenStore tokens,
                         IngestionCoordinator coordinator, int maxBodyBytes) throws IOException {
        this.tokens = Objects.requireNonNull(tokens, "tokens");
        this.coordinator = Objects.requireNonNull(coordinator, "coordinator");
        this.maxBodyBytes = maxBodyBytes;
        this.server = HttpServer.create(new InetSocketAddress(host, port), 0);
        this.httpExecutor = new ThreadPoolExecutor(
                1, 4, 30L, TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(64),
                new ThreadFactory() {
                    private final AtomicLong seq = new AtomicLong();
                    @Override public Thread newThread(Runnable r) {
                        Thread t = new Thread(r, "wazuh-http-" + seq.incrementAndGet());
                        t.setDaemon(true);
                        return t;
                    }
                },
                new ThreadPoolExecutor.AbortPolicy());
        this.server.setExecutor(this.httpExecutor);
        this.server.createContext(AppConfig.WEBHOOK_PATH, new WebHookHandler());
    }

    public void start() { server.start(); }

    public int boundPort() { return server.getAddress().getPort(); }

    public Counts snapshotCounts() {
        return new Counts(accepted.get(), malformed.get(), unauthorized.get(),
                oversized.get(), methodNotAllowed.get(), dropped.get());
    }

    @Override
    public void close() {
        server.stop(1);
        httpExecutor.shutdown();
        try {
            if (!httpExecutor.awaitTermination(3, TimeUnit.SECONDS)) {
                httpExecutor.shutdownNow();
            }
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            httpExecutor.shutdownNow();
        }
    }

    public static final class Counts {
        public final long accepted;
        public final long malformed;
        public final long unauthorized;
        public final long oversized;
        public final long methodNotAllowed;
        public final long dropped;

        public Counts(long accepted, long malformed, long unauthorized,
                      long oversized, long methodNotAllowed, long dropped) {
            this.accepted = accepted;
            this.malformed = malformed;
            this.unauthorized = unauthorized;
            this.oversized = oversized;
            this.methodNotAllowed = methodNotAllowed;
            this.dropped = dropped;
        }
    }

    private final class WebHookHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            try {
                String method = exchange.getRequestMethod().toUpperCase(Locale.ROOT);
                if (!"POST".equals(method)) {
                    if ("OPTIONS".equals(method)) {
                        exchange.getResponseHeaders().add("Allow", "POST, OPTIONS");
                        exchange.sendResponseHeaders(204, -1);
                        exchange.close();
                        return;
                    }
                    methodNotAllowed.incrementAndGet();
                    exchange.getResponseHeaders().add("Allow", "POST, OPTIONS");
                    writeJson(exchange, 405, error("method_not_allowed", "Solo POST u OPTIONS"));
                    return;
                }

                String auth = exchange.getRequestHeaders().getFirst("Authorization");
                if (!tokens.matches(auth)) {
                    unauthorized.incrementAndGet();
                    writeJson(exchange, 401, error("unauthorized", "Token Bearer ausente o inválido"));
                    return;
                }

                long declared = -1L;
                String cl = exchange.getRequestHeaders().getFirst("Content-Length");
                if (cl != null) {
                    try { declared = Long.parseLong(cl.trim()); }
                    catch (NumberFormatException ignore) { declared = -1L; }
                }
                if (declared > maxBodyBytes) {
                    oversized.incrementAndGet();
                    writeJson(exchange, 413, error("payload_too_large",
                            "Cuerpo excede " + maxBodyBytes + " bytes"));
                    return;
                }

                byte[] body;
                try (InputStream in = exchange.getRequestBody()) {
                    body = readCapped(in, declared);
                } catch (BodyTooLargeException btl) {
                    oversized.incrementAndGet();
                    writeJson(exchange, 413, error("payload_too_large",
                            "Cuerpo excede " + maxBodyBytes + " bytes"));
                    return;
                }

                Alert alert;
                try {
                    String json = new String(body, StandardCharsets.UTF_8);
                    if (json.isEmpty()) {
                        malformed.incrementAndGet();
                        writeJson(exchange, 400, error("malformed", "Cuerpo vacío"));
                        return;
                    }
                    alert = parser.parse(json);
                } catch (IllegalArgumentException | JsonParseException ex) {
                    malformed.incrementAndGet();
                    writeJson(exchange, 400, error("malformed", "JSON inválido o regla/fecha fuera de rango"));
                    return;
                }

                boolean acceptedQueue;
                try {
                    acceptedQueue = coordinator.submit(alert);
                } catch (RejectedExecutionException rex) {
                    dropped.incrementAndGet();
                    writeJson(exchange, 503, error("queue_full", "Cola de ingesta saturada"));
                    return;
                }
                if (!acceptedQueue) {
                    dropped.incrementAndGet();
                    writeJson(exchange, 503, error("queue_full", "Cola de ingesta saturada"));
                    return;
                }
                accepted.incrementAndGet();
                JsonObject ok = new JsonObject();
                ok.addProperty("status", "accepted");
                ok.addProperty("alertId", alert.id());
                writeJson(exchange, 202, ok);
            } catch (RuntimeException unexpected) {
                // No se filtra el detalle al cliente; sólo se cierra el intercambio.
                writeJson(exchange, 500, error("internal_error", "Error interno no esperado"));
            } finally {
                exchange.close();
            }
        }
    }

    private byte[] readCapped(InputStream in, long declared) throws IOException, BodyTooLargeException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        long limit = maxBodyBytes;
        long total = 0;
        int n;
        while ((n = in.read(chunk)) != -1) {
            total += n;
            if (total > limit) {
                throw new BodyTooLargeException();
            }
            int take = (int) Math.min(n, limit - (total - n));
            if (take > 0) buffer.write(chunk, 0, take);
        }
        if (declared > 0 && total != declared && total > limit) {
            throw new BodyTooLargeException();
        }
        return buffer.toByteArray();
    }

    private static void writeJson(HttpExchange ex, int code, JsonObject body) throws IOException {
        byte[] payload = body.toString().getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.sendResponseHeaders(code, payload.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(payload);
        }
    }

    private static JsonObject error(String code, String message) {
        JsonObject o = new JsonObject();
        o.addProperty("error", code);
        o.addProperty("message", message);
        return o;
    }

    private static final class BodyTooLargeException extends IOException {
        BodyTooLargeException() { super("oversized"); }
    }
}