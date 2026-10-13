package edu.up.wazuh.app;

import edu.up.wazuh.events.EventStore;
import edu.up.wazuh.ldap.DirectoryLookup;
import edu.up.wazuh.model.Alert;
import edu.up.wazuh.model.DirectoryUser;

import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Coordina la ingesta de alertas: una cola acotada y un pool acotado ejecutan
 * la normalización LDAP sin bloquear el hilo HTTP ni el EDT.
 *
 * <p>Estados LDAP normalizados (lo que aparece en {@code EventStore.Entry.ldapStatus}):
 * <ul>
 *   <li>{@code found}: el usuario se resolvió correctamente.</li>
 *   <li>{@code missing}: la búsqueda se hizo pero no devolvió resultados.</li>
 *   <li>{@code error}: la búsqueda lanzó una excepción; no se expone el detalle.</li>
 *   <li>{@code not-applicable}: el evento no incluye nombre de usuario.</li>
 *   <li>{@code not-configured}: no hay lookup configurado (modo live sin
 *       variables LDAP y modo demo sólo si se omite el lookup explícito).</li>
 * </ul>
 */
public final class IngestionCoordinator implements AutoCloseable {

    public static final String LDAP_FOUND = "found";
    public static final String LDAP_MISSING = "missing";
    public static final String LDAP_ERROR = "error";
    public static final String LDAP_NOT_APPLICABLE = "not-applicable";
    public static final String LDAP_NOT_CONFIGURED = "not-configured";

    private final EventStore store;
    private final DirectoryLookup lookup;
    private final ThreadPoolExecutor executor;
    private final BlockingQueue<Runnable> queue;
    private final AtomicLong rejected = new AtomicLong();
    private final boolean configured;

    public IngestionCoordinator(EventStore store, DirectoryLookup lookup,
                                int queueCapacity, int workerCount) {
        this.store = Objects.requireNonNull(store, "store");
        this.lookup = lookup;
        this.configured = lookup != null;
        this.queue = new ArrayBlockingQueue<>(Math.max(8, queueCapacity));
        ThreadFactory tf = new ThreadFactory() {
            private final AtomicLong seq = new AtomicLong();
            @Override public Thread newThread(Runnable r) {
                Thread t = new Thread(r, "wazuh-ingest-" + seq.incrementAndGet());
                t.setDaemon(true);
                return t;
            }
        };
        this.executor = new ThreadPoolExecutor(
                Math.max(1, workerCount),
                Math.max(1, workerCount),
                30L, TimeUnit.SECONDS,
                queue, tf,
                new ThreadPoolExecutor.AbortPolicy());
    }

    public boolean submit(Alert alert) {
        Objects.requireNonNull(alert, "alert");
        try {
            executor.execute(() -> process(alert));
            return true;
        } catch (RejectedExecutionException ex) {
            rejected.incrementAndGet();
            return false;
        }
    }

    public long rejectedCount() { return rejected.get(); }
    public boolean configured() { return configured; }

    void process(Alert alert) {
        DirectoryUser user = null;
        String status;
        if (!configured) {
            status = LDAP_NOT_CONFIGURED;
        } else if (alert.username() == null || alert.username().isEmpty()) {
            status = LDAP_NOT_APPLICABLE;
        } else {
            try {
                Optional<DirectoryUser> result = lookup.find(alert.username());
                if (result.isPresent()) {
                    user = result.get();
                    status = LDAP_FOUND;
                } else {
                    status = LDAP_MISSING;
                }
            } catch (Throwable t) {
                // No se expone la causa ni el nombre de usuario al registro.
                user = null;
                status = LDAP_ERROR;
            }
        }
        store.add(alert, user, status);
    }

    @Override
    public void close() {
        executor.shutdown();
        try {
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            executor.shutdownNow();
        }
    }
}