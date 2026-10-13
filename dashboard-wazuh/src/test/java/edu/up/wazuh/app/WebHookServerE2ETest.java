package edu.up.wazuh.app;

import edu.up.wazuh.events.EventStore;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * E2E real del receptor de webhooks: HttpServer real, HttpClient real, parser real,
 * coordinador real. Sin mocks externos; todo se ejecuta en loopback dentro del mismo JVM.
 *
 * <p>Excluido del surefire normal (ver pom.xml); debe ejecutarse en el verify central
 * del orquestador para evitar inicializar el receptor en cada clase de tests.
 */
class WebHookServerE2ETest {

    private EventStore store;
    private IngestionCoordinator ingestion;
    private TokenStore tokens;
    private WebHookServer server;
    private HttpClient client;

    @BeforeEach
    void setUp() throws Exception {
        store = new EventStore(64);
        ingestion = new IngestionCoordinator(store, null, 16, 2);
        tokens = new TokenStore("e2e-token-1234567890abcdef");
        server = new WebHookServer("127.0.0.1", 0, tokens, ingestion);
        server.start();
        client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();
    }

    @AfterEach
    void tearDown() {
        if (server != null) server.close();
        if (ingestion != null) ingestion.close();
    }

    private URI uri() {
        return URI.create("http://127.0.0.1:" + server.boundPort() + AppConfig.WEBHOOK_PATH);
    }

    private String alertJson(String id) {
        return "{\"id\":\"" + id + "\",\"timestamp\":\"2026-10-13T08:00:00Z\","
                + "\"agent\":{\"id\":\"001\",\"name\":\"web-panama\"},"
                + "\"rule\":{\"id\":\"5715\",\"level\":3,\"description\":\"SSH login\"},"
                + "\"data\":{\"srcuser\":\"agarcia\"},"
                + "\"country\":\"Panama\","
                + "\"geoLocation\":{\"latitude\":8.98,\"longitude\":-79.51},"
                + "\"integration\":\"custom-dashboard\"}";
    }

    private HttpResponse<String> send(String method, String body, String authHeader) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(uri())
                .timeout(Duration.ofSeconds(5));
        if (authHeader != null) b.header("Authorization", authHeader);
        if (body == null) {
            b.method(method, HttpRequest.BodyPublishers.noBody());
        } else {
            b.header("Content-Type", "application/json");
            b.method(method, HttpRequest.BodyPublishers.ofByteArray(body.getBytes(StandardCharsets.UTF_8)));
        }
        return client.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void postValidoDevuelve202YAlertavaAlStore() throws Exception {
        HttpResponse<String> r = send("POST", alertJson("e2e-001"), tokens.headerValue());
        assertEquals(202, r.statusCode(), "POST válido debe ser aceptado");
        waitForStore(1);
        assertEquals(1, store.size());
        assertEquals("e2e-001", store.snapshot().get(0).alert().id());
    }

    @Test
    void sinAuthorizationDevuelve401() throws Exception {
        HttpResponse<String> r = send("POST", alertJson("e2e-002"), null);
        assertEquals(401, r.statusCode());
    }

    @Test
    void tokenIncorrectoDevuelve401() throws Exception {
        HttpResponse<String> r = send("POST", alertJson("e2e-003"), "Bearer incorrecto");
        assertEquals(401, r.statusCode());
    }

    @Test
    void metodoGetDevuelve405() throws Exception {
        HttpResponse<String> r = send("GET", null, tokens.headerValue());
        assertEquals(405, r.statusCode());
    }

    @Test
    void metodoPutDevuelve405() throws Exception {
        HttpResponse<String> r = send("PUT", alertJson("e2e-004"), tokens.headerValue());
        assertEquals(405, r.statusCode());
    }

    @Test
    void cuerpoVacioDevuelve400() throws Exception {
        HttpResponse<String> r = send("POST", "", tokens.headerValue());
        assertEquals(400, r.statusCode());
    }

    @Test
    void jsonInvalidoDevuelve400() throws Exception {
        HttpResponse<String> r = send("POST", "{ esto no es json", tokens.headerValue());
        assertEquals(400, r.statusCode());
    }

    @Test
    void jsonConSeveridadFueraDeRangoDevuelve400() throws Exception {
        // Regla como objeto anidado {id, level} con timestamp válido para que
        // el parser llegue a la validación 0..15 (no salga antes por 'rule required').
        String bad = "{\"id\":\"e2e-bad\",\"timestamp\":\"2026-10-13T08:00:00Z\","
                + "\"agent\":\"001\",\"rule\":{\"id\":\"5715\",\"level\":99},"
                + "\"description\":\"out of range\"}";
        HttpResponse<String> r = send("POST", bad, tokens.headerValue());
        assertEquals(400, r.statusCode());
    }

    @Test
    void cuerpoOversizedDevuelve413() throws Exception {
        StringBuilder sb = new StringBuilder("{\"id\":\"e2e-big\",\"description\":\"");
        // 1 MiB + slack
        int target = AppConfig.MAX_BODY_BYTES + 4096;
        while (sb.length() < target) sb.append('A');
        sb.append("\"}");
        HttpResponse<String> r = send("POST", sb.toString(), tokens.headerValue());
        assertEquals(413, r.statusCode());
    }

    @Test
    void concurrenteNoPierdeEventos() throws Exception {
        int N = 30;
        Thread[] senders = new Thread[N];
        for (int i = 0; i < N; i++) {
            final int idx = i;
            senders[i] = new Thread(() -> {
                try {
                    send("POST", alertJson("e2e-conc-" + idx), tokens.headerValue());
                } catch (Exception ignored) {}
            }, "e2e-sender-" + i);
        }
        for (Thread t : senders) t.start();
        for (Thread t : senders) t.join();
        waitForStore(N);
        assertEquals(N, store.size(),
                "Tras concurrencia, todos los IDs únicos deben estar en el store. seen="
                        + store.size() + " expected=" + N);
    }

    @Test
    void autenticacionIncorrectaEnConcurrenciaNoMezclaConteos() throws Exception {
        Thread[] t = new Thread[20];
        final boolean[] done = new boolean[t.length];
        for (int i = 0; i < t.length; i++) {
            final int idx = i;
            t[i] = new Thread(() -> {
                try {
                    String auth = (idx % 2 == 0) ? "Bearer incorrecto" : tokens.headerValue();
                    String body = (idx % 2 == 0) ? "x" : alertJson("auth-conc-" + idx);
                    HttpResponse<String> r = send("POST", body, auth);
                    assertTrue(r.statusCode() == 401 || r.statusCode() == 202);
                    done[idx] = true;
                } catch (Exception ignored) {}
            });
        }
        for (Thread th : t) th.start();
        for (Thread th : t) th.join();
        for (boolean d : done) assertTrue(d, "Todas las hebras deben completar");
        WebHookServer.Counts c = server.snapshotCounts();
        assertEquals(10, c.unauthorized);
        assertEquals(10, c.accepted);
        assertEquals(0, c.malformed, "Los 401 no deben contar como malformed");
    }

    private void waitForStore(int expected) throws InterruptedException {
        long deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos();
        while (store.size() < expected && System.nanoTime() < deadline) {
            Thread.sleep(25);
        }
    }
}