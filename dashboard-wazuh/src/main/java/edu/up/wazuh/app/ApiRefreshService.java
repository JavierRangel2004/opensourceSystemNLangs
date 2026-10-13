package edu.up.wazuh.app;

import edu.up.wazuh.api.WazuhApiClient;
import edu.up.wazuh.model.Agent;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Refresca los agentes del manager en segundo plano, sólo cuando hay configuración real.
 * Reporta un estado saneado (sin credenciales, sin URL completa, sólo un motivo).
 * <p>Si no está configurado, no inventa datos: el estado es {@code not-configured}.
 */
public final class ApiRefreshService implements AutoCloseable {

    public enum Mode { CONFIGURED, NOT_CONFIGURED }

    public static final class State {
        public final Mode mode;
        public final String status;
        public final List<Agent> agents;
        public final long lastUpdatedMs;

        public State(Mode mode, String status, List<Agent> agents, long lastUpdatedMs) {
            this.mode = mode;
            this.status = status;
            this.agents = agents == null ? List.of() : List.copyOf(agents);
            this.lastUpdatedMs = lastUpdatedMs;
        }

        public static State notConfigured() {
            return new State(Mode.NOT_CONFIGURED, "not-configured", List.of(), 0L);
        }
    }

    private final WazuhApiClient client;
    private final ScheduledExecutorService scheduler;
    private final AtomicReference<State> state;
    private final long intervalMs;
    private final String statusSink;
    private volatile ScheduledFuture<?> task;

    public ApiRefreshService(WazuhApiClient client, long intervalMs, String statusSink) {
        this.client = client;
        this.intervalMs = intervalMs;
        this.statusSink = statusSink == null ? "" : statusSink;
        if (client == null) {
            this.scheduler = null;
            this.state = new AtomicReference<>(State.notConfigured());
        } else {
            this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "wazuh-api-refresh");
                t.setDaemon(true);
                return t;
            });
            this.state = new AtomicReference<>(State.notConfigured());
        }
    }

    public State current() { return state.get(); }

    public void start() {
        if (scheduler == null) return;
        if (task != null) return;
        task = scheduler.scheduleAtFixedRate(this::tick,
                0L, Math.max(1_000L, intervalMs), TimeUnit.MILLISECONDS);
    }

    /** Ejecuta una iteración del refresco; útil para pruebas deterministas. */
    void tick() {
        Objects.requireNonNull(client);
        try {
            List<Agent> agents = client.fetchAgents();
            State next = new State(Mode.CONFIGURED, "ok:" + agents.size(), agents, System.currentTimeMillis());
            state.set(next);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        } catch (Throwable t) {
            // Estado saneado: sólo el motivo del error, sin URL ni credenciales.
            String reason = t.getClass().getSimpleName();
            state.set(new State(Mode.CONFIGURED, "error:" + reason, List.of(), System.currentTimeMillis()));
        }
    }

    public String statusMessage() {
        State s = state.get();
        String base = s.status == null ? "" : s.status;
        return statusSink.isEmpty() ? base : statusSink + ":" + base;
    }

    @Override
    public void close() {
        if (scheduler == null) return;
        scheduler.shutdown();
        try {
            if (!scheduler.awaitTermination(3, TimeUnit.SECONDS)) {
                scheduler.shutdownNow();
            }
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            scheduler.shutdownNow();
        }
    }
}