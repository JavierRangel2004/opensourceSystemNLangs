package edu.up.wazuh.app;

import edu.up.wazuh.api.WazuhApiClient;
import edu.up.wazuh.events.EventStore;
import edu.up.wazuh.ldap.DirectoryLookup;
import edu.up.wazuh.ldap.JndiDirectoryLookup;
import edu.up.wazuh.model.Alert;
import edu.up.wazuh.ui.DashboardPanel;

import javax.swing.JFrame;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.WindowConstants;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.net.URI;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Punto de entrada CLI del dashboard.
 *
 * <ul>
 *   <li>{@code --demo}: muestra sintética, sin credenciales, sin LDAP real, sin manager.</li>
 *   <li>{@code --live}: usa variables de entorno para la API del manager y el LDAP/AD.</li>
 *   <li>{@code --demo --headless-smoke}: receptor + envío + render PNG en una corrida.</li>
 * </ul>
 *
 * <p>{@code --demo} y {@code --live} son mutuamente excluyentes. Sin argumentos se
 * imprime la ayuda y se sale con código 2. En modo live, la variable de entorno
 * {@code WEBHOOK_TOKEN} es obligatoria: sin ella el Integrator no puede
 * autenticarse con el receptor.</p>
 */
public final class DashboardApplication {

    private static final String USAGE =
            "Uso: java -jar dashboard-wazuh.jar [--demo | --live] [--headless-smoke] [--port=N]\n"
                    + "    [--host=X] [--output=PATH] [--demo-resource=PATH]\n"
                    + "Variables de entorno relevantes:\n"
                    + "    WEBHOOK_TOKEN          Bearer del receptor (obligatorio en --live)\n"
                    + "    WAZUH_API_URL/USER/PASSWORD   manager API (modo --live)\n"
                    + "    LDAP_URL/BIND_DN/BIND_PASSWORD/BASE_DN   LDAP/AD (modo --live, opcional)\n"
                    + "    DASHBOARD_HOST / DASHBOARD_PORT / DASHBOARD_OUTPUT / DASHBOARD_DEMO_RESOURCE\n";

    private DashboardApplication() {}

    public static void main(String[] args) {
        try {
            int code = run(args);
            if (code != 0) System.exit(code);
        } catch (IllegalArgumentException ex) {
            System.err.println("Error: " + ex.getMessage());
            System.err.println(USAGE);
            System.exit(2);
        } catch (Exception ex) {
            System.err.println("Fallo inesperado: " + ex.getClass().getSimpleName()
                    + (ex.getMessage() == null ? "" : (": " + ex.getMessage())));
            ex.printStackTrace(System.err);
            System.exit(1);
        }
    }

    private static int run(String[] args) throws Exception {
        AppConfig cfg = AppConfig.fromEnv(args);
        validateConfig(cfg);
        System.setProperty("java.awt.headless", cfg.headlessSmoke() ? "true" : "false");

        String envToken = System.getenv("WEBHOOK_TOKEN");
        if (cfg.live() && (envToken == null || envToken.isBlank())) {
            System.err.println("Error: WEBHOOK_TOKEN es obligatorio en modo --live; "
                    + "el Integrator no puede autenticarse sin él.");
            System.err.println(USAGE);
            return 2;
        }

        EventStore store = new EventStore(1024);
        // En --demo el token SIEMPRE es nuevo runtime: nunca se mezcla el
        // token exportado (potencialmente del manager real) con la muestra.
        // Sólo --live honra WEBHOOK_TOKEN del entorno.
        TokenStore tokens = new TokenStore(cfg.live() ? envToken : null);
        DirectoryLookup lookup = cfg.demo() ? new DemoDirectoryLookup() : buildLdapLookup();

        IngestionCoordinator ingestion = null;
        WebHookServer server = null;
        ApiRefreshService api = null;
        try {
            ingestion = new IngestionCoordinator(
                    store, lookup,
                    AppConfig.DEFAULT_INGEST_QUEUE, AppConfig.DEFAULT_INGEST_WORKERS);

            server = new WebHookServer(
                    cfg.webhookHost(), cfg.webhookPort(), tokens, ingestion);
            server.start();

            api = new ApiRefreshService(
                    buildApiClient(cfg),
                    AppConfig.DEFAULT_API_REFRESH_MS,
                    "api");

            List<Alert> rebasedDemo = List.of();
            if (cfg.demo()) {
                rebasedDemo = DemoDataLoader.loadAndIngest(cfg.demoResource(), store, ingestion);
            }
            if (cfg.live()) {
                api.start();
            }

            if (cfg.demo() && cfg.headlessSmoke()) {
                HeadlessSmokeRunner.Report report = runSmoke(cfg, store, tokens, server,
                        rebasedDemo);
                System.out.println(report.format());
                return 0;
            }
            runUi(cfg, store, server, api);
            return 0;
        } finally {
            closeQuietly(api);
            closeQuietly(server);
            closeQuietly(ingestion);
            if (lookup != null) {
                try { lookup.close(); } catch (RuntimeException ignore) {}
            }
        }
    }

    private static void validateConfig(AppConfig cfg) {
        if (!cfg.demo() && !cfg.live() && !cfg.headlessSmoke()) {
            System.out.println(USAGE);
            throw new IllegalArgumentException("Sin modo: especifique --demo o --live");
        }
        if (cfg.demo() && cfg.live()) {
            throw new IllegalArgumentException("--demo y --live son mutuamente excluyentes");
        }
        if (cfg.headlessSmoke() && !cfg.demo()) {
            throw new IllegalArgumentException("--headless-smoke requiere --demo");
        }
    }

    private static JndiDirectoryLookup buildLdapLookup() {
        String url = System.getenv("LDAP_URL");
        String dn = System.getenv("LDAP_BIND_DN");
        String pw = System.getenv("LDAP_BIND_PASSWORD");
        String base = System.getenv("LDAP_BASE_DN");
        if (url == null || dn == null || pw == null || base == null) return null;
        return new JndiDirectoryLookup(url, dn, pw, base);
    }

    private static WazuhApiClient buildApiClient(AppConfig cfg) {
        if (cfg.demo()) return null;
        String url = System.getenv("WAZUH_API_URL");
        String user = System.getenv("WAZUH_API_USER");
        String pw = System.getenv("WAZUH_API_PASSWORD");
        if (url == null || user == null || pw == null) return null;
        return new WazuhApiClient(URI.create(url), user, pw);
    }

    private static HeadlessSmokeRunner.Report runSmoke(AppConfig cfg, EventStore store,
                                                       TokenStore tokens, WebHookServer server,
                                                       List<Alert> demoAlerts) throws Exception {
        HeadlessSmokeRunner runner = new HeadlessSmokeRunner(cfg, store, tokens, server, demoAlerts);
        return runner.run();
    }

    private static void runUi(AppConfig cfg, EventStore store, WebHookServer server,
                              ApiRefreshService api) throws Exception {
        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<Timer> apiTimerRef = new AtomicReference<>();

        SwingUtilities.invokeAndWait(() -> {
            DashboardPanel panel = new DashboardPanel(store, cfg.demo());
            panel.setStatus(initialStatus(cfg, api));
            JFrame frame = new JFrame(cfg.demo() ? "Dashboard Wazuh — DEMO (MUESTRA)" : "Dashboard Wazuh");
            frame.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
            frame.setSize(1280, 800);
            frame.setContentPane(panel);
            frame.setLocationRelativeTo(null);
            frame.addWindowListener(new WindowAdapter() {
                @Override public void windowClosing(WindowEvent e) {
                    latch.countDown();
                }
                @Override public void windowClosed(WindowEvent e) {
                    Timer t = apiTimerRef.get();
                    if (t != null && t.isRunning()) t.stop();
                    panel.stopAutoRefresh();
                }
            });
            frame.setVisible(true);

            // Timer EDT que refresca las vistas con el snapshot del store en
            // ambos modos (demo y live). Sin esto, los POST por webhook que
            // lleguen después del arranque nunca aparecen, y el filtro
            // "Última 1h" no se vuelve a evaluar.
            Timer refreshTimer = new Timer(2000, e -> {
                if (cfg.live() && api != null) {
                    ApiRefreshService.State s = api.current();
                    panel.setAgents(s.agents);
                    panel.setStatus("api:" + s.status);
                } else {
                    // DashboardPanel deriva agentes reales desde los eventos.
                    panel.setAgents(List.of());
                }
            });
            refreshTimer.setRepeats(true);
            refreshTimer.start();
            apiTimerRef.set(refreshTimer);
        });
        System.out.println("dashboard-receptor: " + cfg.webhookHost() + ":" + server.boundPort()
                + " mode=" + (cfg.demo() ? "demo" : cfg.live() ? "live" : "idle"));
        latch.await();
    }

    private static String initialStatus(AppConfig cfg, ApiRefreshService api) {
        if (cfg.demo()) return "demo";
        return api.statusMessage();
    }

    private static void closeQuietly(AutoCloseable c) {
        if (c == null) return;
        try { c.close(); } catch (Exception ignore) {}
    }

    static String usage() { return USAGE; }
}