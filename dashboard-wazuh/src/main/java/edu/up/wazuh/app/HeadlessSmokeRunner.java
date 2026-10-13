package edu.up.wazuh.app;

import com.google.gson.JsonObject;
import edu.up.wazuh.events.EventStore;
import edu.up.wazuh.model.Alert;
import edu.up.wazuh.ui.DashboardPanel;

import javax.imageio.ImageIO;
import javax.swing.SwingUtilities;
import java.awt.Dimension;
import java.awt.image.BufferedImage;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Locale;

/**
 * Smoke central del dashboard: arranca el receptor real, envía una alerta de muestra por HTTP,
 * espera determinísticamente al store, renderiza el panel en el EDT a un PNG y apaga todo.
 *
 * <p>No imprime secretos: el token se inyecta mediante {@link TokenStore#headerValue()} al
 * emisor interno; los conteos se reportan sin IDs sensibles.
 */
public final class HeadlessSmokeRunner {

    private static final int RENDER_WIDTH = 1280;
    private static final int RENDER_HEIGHT = 800;
    private static final Duration WAIT_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration POLL = Duration.ofMillis(50);

    private final AppConfig config;
    private final EventStore store;
    private final TokenStore tokens;
    private final WebHookServer server;
    private final List<Alert> demoAlerts;

    public HeadlessSmokeRunner(AppConfig config, EventStore store, TokenStore tokens,
                               WebHookServer server, List<Alert> demoAlerts) {
        this.config = config;
        this.store = store;
        this.tokens = tokens;
        this.server = server;
        this.demoAlerts = demoAlerts;
    }

    public Report run() throws Exception {
        Path output = resolveOutput(config.outputImagePath());
        if (demoAlerts == null || demoAlerts.isEmpty()) {
            throw new IllegalStateException("Smoke requiere alertas demo cargadas");
        }
        // DemoDataLoader.rebaseAndIngest garantiza que las N alertas demo
        // están en el store antes de invocar al smoke. La línea base es exacta.
        long baseline = demoAlerts.size();
        long target = baseline + 1;
        if (store.size() < baseline) {
            throw new IllegalStateException("Smoke: store aún no contiene las " + baseline
                    + " alertas demo (tiene " + store.size() + ")");
        }
        // Fixture del smoke: una alerta nueva con id único y timestamp actual,
        // basada en la primera alerta demo (mantiene regla, agente, usuario
        // y país para que la vista refleje datos coherentes).
        Alert fixture = withFreshIdAndTimestamp(demoAlerts.get(0));

        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(WAIT_TIMEOUT)
                .build();
        HttpResponse<String> response;
        try {
            URI endpoint = URI.create("http://" + config.webhookHost() + ":" + server.boundPort()
                    + AppConfig.WEBHOOK_PATH);
            HttpRequest req = HttpRequest.newBuilder(endpoint)
                    .header("Authorization", tokens.headerValue())
                    .header("Content-Type", "application/json")
                    .timeout(WAIT_TIMEOUT)
                    .POST(HttpRequest.BodyPublishers.ofByteArray(buildPayload(fixture)))
                    .build();
            response = client.send(req, HttpResponse.BodyHandlers.ofString());
        } finally {
            // JDK 17: HttpClient no implementa AutoCloseable. El cliente es
            // ligero y se cierra cuando el subproceso del executor termina.
            // No requiere try-with-resources.
        }

        if (response.statusCode() != 202) {
            throw new IllegalStateException("Smoke: receptor respondió " + response.statusCode()
                    + " cuerpo=" + truncate(response.body(), 200));
        }

        long deadline = System.nanoTime() + WAIT_TIMEOUT.toNanos();
        while (System.nanoTime() < deadline && store.size() < target) {
            Thread.sleep(POLL.toMillis());
        }
        if (store.size() < target) {
            throw new IllegalStateException("Smoke: store no recibió la alerta (esperado "
                    + target + ", obtuvo " + store.size() + ")");
        }

        Path rendered = renderPanel(output);

        WebHookServer.Counts c = server.snapshotCounts();
        return new Report(
                true,
                response.statusCode(),
                store.size(),
                c.accepted, c.malformed, c.unauthorized, c.oversized, c.methodNotAllowed, c.dropped,
                rendered.toAbsolutePath().toString(),
                tokens.generatedRuntime());
    }

    private byte[] buildPayload(Alert fixture) {
        JsonObject payload = new JsonObject();
        payload.addProperty("id", "smoke-" + System.nanoTime());
        payload.addProperty("timestamp", fixture.timestamp().toString());
        JsonObject rule = new JsonObject();
        rule.addProperty("id", fixture.ruleId());
        rule.addProperty("level", fixture.level());
        rule.addProperty("description", fixture.description());
        payload.add("rule", rule);
        JsonObject agent = new JsonObject();
        agent.addProperty("id", fixture.agentId());
        agent.addProperty("name", fixture.agentName());
        payload.add("agent", agent);
        // Wazuh format: el usuario va en data.srcuser (no en la raíz).
        JsonObject data = new JsonObject();
        data.addProperty("srcuser", fixture.username());
        payload.add("data", data);
        payload.addProperty("country", fixture.country());
        if (fixture.latitude() != null && fixture.longitude() != null) {
            JsonObject geo = new JsonObject();
            geo.addProperty("latitude", fixture.latitude());
            geo.addProperty("longitude", fixture.longitude());
            payload.add("geoLocation", geo);
        }
        payload.addProperty("integration", fixture.integration());
        return payload.toString().getBytes(StandardCharsets.UTF_8);
    }

    private Alert withFreshIdAndTimestamp(Alert base) {
        Instant now = Instant.now();
        return new Alert("smoke-" + System.nanoTime(), now,
                base.agentId(), base.agentName(), base.ruleId(), base.level(),
                base.description(), base.username(), base.country(),
                base.latitude(), base.longitude(), base.integration());
    }

    private Path renderPanel(Path output) throws Exception {
        Path parent = output.toAbsolutePath().getParent();
        if (parent != null) Files.createDirectories(parent);
        final DashboardPanel[] panelRef = new DashboardPanel[1];
        final boolean[] ok = new boolean[1];
        SwingUtilities.invokeAndWait(() -> {
            try {
                DashboardPanel panel = new DashboardPanel(store, true);
                panel.setAgents(List.of());
                panel.setStatus("smoke-demo");
                panel.setPreferredSize(new Dimension(RENDER_WIDTH, RENDER_HEIGHT));
                panel.setBounds(0, 0, RENDER_WIDTH, RENDER_HEIGHT);
                panel.doLayout();
                panel.validate();
                panel.stopAutoRefresh();
                ok[0] = true;
                panelRef[0] = panel;
            } catch (RuntimeException ex) {
                ok[0] = false;
            }
        });
        if (!ok[0] || panelRef[0] == null) {
            throw new IllegalStateException("Smoke: no se pudo construir DashboardPanel en EDT");
        }
        final DashboardPanel panel = panelRef[0];
        final BufferedImage[] imgRef = new BufferedImage[1];
        SwingUtilities.invokeAndWait(() -> {
            panel.refresh();
            imgRef[0] = panel.renderToImage();
        });
        BufferedImage img = imgRef[0];
        if (img == null) throw new IllegalStateException("Smoke: render vacío");

        // Verificación: tras el render, el panel refleja el conteo esperado
        // (12 demo + 1 smoke = 13). Si no, el filtro "Última 1h" o la ingestión
        // están vacíos — el smoke no debe quedarse en un PNG "noempty" genérico.
        final int[] visibleEvents = new int[1];
        final int[] geoSymbols = new int[1];
        final int[] noLocation = new int[1];
        SwingUtilities.invokeAndWait(() -> {
            visibleEvents[0] = panel.eventTablePanel().entryCount();
            geoSymbols[0] = panel.geoMapPanel().symbolCount();
            noLocation[0] = panel.geoMapPanel().noLocationCount();
        });
        int expected = (int) (demoAlerts.size() + 1L);
        if (visibleEvents[0] != expected) {
            throw new IllegalStateException("Smoke: panel muestra " + visibleEvents[0]
                    + " eventos, esperado " + expected
                    + " (filtro 'Última 1h' probablemente excluye las alertas demo)");
        }
        if (geoSymbols[0] != 9) {
            throw new IllegalStateException("Smoke: mapa con " + geoSymbols[0]
                    + " puntos geográficos; esperado 9");
        }
        if (noLocation[0] != 3) {
            throw new IllegalStateException("Smoke: hay " + noLocation[0]
                    + " eventos sin ubicación; esperado 3");
        }

        // Estado LDAP: 11 found (10 demo con srcuser + 1 smoke con srcuser),
        // 2 not-applicable (demo-006 y demo-012 con srcuser=''). Se cuentan
        // sobre el store real para no depender del resumen del panel.
        int found = 0, notApplicable = 0;
        for (EventStore.Entry e : store.snapshot()) {
            String s = e.ldapStatus();
            if (s == null) continue;
            if (s.equals(IngestionCoordinator.LDAP_FOUND)) found++;
            else if (s.equals(IngestionCoordinator.LDAP_NOT_APPLICABLE)) notApplicable++;
        }
        int expectedFound = 11;
        int expectedNotApplicable = 2;
        if (found != expectedFound || notApplicable != expectedNotApplicable) {
            throw new IllegalStateException("Smoke: LDAP statuses encontrados="
                    + found + "/esperado=" + expectedFound
                    + " not-applicable=" + notApplicable
                    + "/esperado=" + expectedNotApplicable
                    + " (parser probablemente no lee data.srcuser)");
        }

        ImageIO.write(img, "png", output.toFile());
        return output;
    }

    private static Path resolveOutput(String path) {
        String p = path == null || path.isBlank() ? "output/dashboard-demo.png" : path;
        return Paths.get(p);
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }

    public static final class Report {
        public final boolean ok;
        public final int httpStatus;
        public final long storeSize;
        public final long accepted;
        public final long malformed;
        public final long unauthorized;
        public final long oversized;
        public final long methodNotAllowed;
        public final long dropped;
        public final String outputPath;
        public final boolean tokenRuntime;

        public Report(boolean ok, int httpStatus, long storeSize,
                      long accepted, long malformed, long unauthorized,
                      long oversized, long methodNotAllowed, long dropped,
                      String outputPath, boolean tokenRuntime) {
            this.ok = ok;
            this.httpStatus = httpStatus;
            this.storeSize = storeSize;
            this.accepted = accepted;
            this.malformed = malformed;
            this.unauthorized = unauthorized;
            this.oversized = oversized;
            this.methodNotAllowed = methodNotAllowed;
            this.dropped = dropped;
            this.outputPath = outputPath;
            this.tokenRuntime = tokenRuntime;
        }

        public String format() {
            return String.format(Locale.ROOT,
                    "smoke.ok=%s http=%d store=%d accepted=%d malformed=%d unauthorized=%d"
                            + " oversized=%d methodNotAllowed=%d dropped=%d token.runtime=%s output=%s",
                    ok, httpStatus, storeSize,
                    accepted, malformed, unauthorized, oversized, methodNotAllowed, dropped,
                    tokenRuntime, outputPath);
        }
    }
}