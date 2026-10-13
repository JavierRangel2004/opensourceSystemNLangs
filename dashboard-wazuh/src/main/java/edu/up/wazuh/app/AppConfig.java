package edu.up.wazuh.app;

import java.util.Locale;
import java.util.Objects;

/**
 * Configuración del runtime del dashboard. Lee únicamente nombres de variables de entorno.
 * No contiene valores secretos: el token Bearer del webhook se genera en memoria y nunca se imprime.
 */
public final class AppConfig {

    /** Tamaño máximo aceptado por el receptor HTTP (1 MiB). */
    public static final int MAX_BODY_BYTES = 1024 * 1024;

    /** Puerto por defecto del receptor (loopback). */
    public static final int DEFAULT_WEBHOOK_PORT = 8787;

    /** Host por defecto del receptor (loopback). */
    public static final String DEFAULT_WEBHOOK_HOST = "127.0.0.1";

    /** Tamaño de la cola de ingesta. */
    public static final int DEFAULT_INGEST_QUEUE = 256;

    /** Número de workers de ingesta/LDAP. */
    public static final int DEFAULT_INGEST_WORKERS = 2;

    /** Intervalo de refresco de agentes en milisegundos. */
    public static final long DEFAULT_API_REFRESH_MS = 30_000L;

    /** Ruta del endpoint HTTP que recibe los webhooks. */
    public static final String WEBHOOK_PATH = "/api/wazuh-events";

    private final boolean demo;
    private final boolean live;
    private final boolean headlessSmoke;
    private final String webhookHost;
    private final int webhookPort;
    private final String outputImagePath;
    private final String demoResource;

    private AppConfig(Builder b) {
        this.demo = b.demo;
        this.live = b.live;
        this.headlessSmoke = b.headlessSmoke;
        this.webhookHost = Objects.requireNonNullElse(b.webhookHost, DEFAULT_WEBHOOK_HOST);
        this.webhookPort = b.webhookPort > 0 ? b.webhookPort : DEFAULT_WEBHOOK_PORT;
        this.outputImagePath = Objects.requireNonNullElse(b.outputImagePath, "output/dashboard-demo.png");
        this.demoResource = Objects.requireNonNullElse(b.demoResource, "demo/alerts.json");
    }

    public static AppConfig fromEnv(String[] args) {
        Builder b = new Builder();
        b.demo = false;
        b.live = false;
        b.headlessSmoke = false;
        for (String a : args) {
            String arg = a == null ? "" : a;
            switch (arg) {
                case "--demo" -> b.demo = true;
                case "--live" -> b.live = true;
                case "--headless-smoke" -> b.headlessSmoke = true;
                default -> {
                    if (arg.startsWith("--port=")) {
                        b.webhookPort = parsePort(arg.substring("--port=".length()));
                    } else if (arg.startsWith("--host=")) {
                        b.webhookHost = arg.substring("--host=".length());
                    } else if (arg.startsWith("--output=")) {
                        b.outputImagePath = arg.substring("--output=".length());
                    } else if (arg.startsWith("--demo-resource=")) {
                        b.demoResource = arg.substring("--demo-resource=".length());
                    } else {
                        throw new IllegalArgumentException("Argumento desconocido: " + arg);
                    }
                }
            }
        }
        String envMode = System.getenv("DASHBOARD_MODE");
        if (envMode != null) {
            String mode = envMode.toLowerCase(Locale.ROOT).trim();
            // Modo exacto: demo | live. 'smoke' sólo se activa con --demo --headless-smoke.
            switch (mode) {
                case "demo" -> b.demo = true;
                case "live" -> b.live = true;
                default -> throw new IllegalArgumentException(
                        "DASHBOARD_MODE debe ser exactamente 'demo' o 'live'; fue '" + envMode + "'");
            }
        }
        if (System.getenv("DASHBOARD_HOST") != null) b.webhookHost = System.getenv("DASHBOARD_HOST");
        String portEnv = System.getenv("DASHBOARD_PORT");
        if (portEnv != null) b.webhookPort = parsePort(portEnv);
        if (System.getenv("DASHBOARD_OUTPUT") != null) b.outputImagePath = System.getenv("DASHBOARD_OUTPUT");
        if (System.getenv("DASHBOARD_DEMO_RESOURCE") != null) b.demoResource = System.getenv("DASHBOARD_DEMO_RESOURCE");
        return b.build();
    }

    private static int parsePort(String raw) {
        try {
            int p = Integer.parseInt(raw.trim());
            if (p < 1 || p > 65535) {
                throw new IllegalArgumentException("Puerto fuera de 1..65535: " + p);
            }
            return p;
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException("Puerto inválido: '" + raw + "'");
        }
    }

    public boolean demo() { return demo; }
    public boolean live() { return live; }
    public boolean headlessSmoke() { return headlessSmoke; }
    public String webhookHost() { return webhookHost; }
    public int webhookPort() { return webhookPort; }
    public String outputImagePath() { return outputImagePath; }
    public String demoResource() { return demoResource; }

    public static final class Builder {
        private boolean demo;
        private boolean live;
        private boolean headlessSmoke;
        private String webhookHost;
        private int webhookPort = DEFAULT_WEBHOOK_PORT;
        private String outputImagePath;
        private String demoResource;

        public AppConfig build() { return new AppConfig(this); }
    }
}