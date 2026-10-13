package edu.up.wazuh.app;

import edu.up.wazuh.events.EventStore;
import edu.up.wazuh.ldap.DirectoryLookup;
import edu.up.wazuh.model.Alert;
import edu.up.wazuh.model.DirectoryUser;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class IngestionCoordinatorTest {

    private IngestionCoordinator coordinator;

    @AfterEach
    void cleanup() {
        if (coordinator != null) coordinator.close();
    }

    private static Alert alert(String username) {
        return new Alert("a-" + System.nanoTime(), Instant.parse("2026-10-13T08:00:00Z"),
                "001", "agent", "5715", 3, "demo",
                username == null ? "" : username,
                "Panama", 8.98, -79.51, "custom-dashboard");
    }

    @Test
    void sinLookupConfiguradoMarcaNotConfigured() throws Exception {
        EventStore store = new EventStore(16);
        coordinator = new IngestionCoordinator(store, null, 8, 1);
        coordinator.submit(alert("agarcia"));
        waitFor(store, 1);
        EventStore.Entry e = store.snapshot().get(0);
        assertEquals(IngestionCoordinator.LDAP_NOT_CONFIGURED, e.ldapStatus());
    }

    @Test
    void eventoSinUsuarioMarcaNotApplicable() throws Exception {
        EventStore store = new EventStore(16);
        StubLookup stub = new StubLookup(Optional.empty());
        coordinator = new IngestionCoordinator(store, stub, 8, 1);
        coordinator.submit(alert(""));
        waitFor(store, 1);
        EventStore.Entry e = store.snapshot().get(0);
        assertEquals(IngestionCoordinator.LDAP_NOT_APPLICABLE, e.ldapStatus());
        assertEquals(0, stub.calls.get(), "No debe consultar LDAP sin usuario");
    }

    @Test
    void lookupFoundMarcaFoundConUsuario() throws Exception {
        EventStore store = new EventStore(16);
        DirectoryUser u = new DirectoryUser("agarcia", "Ana García", "ana@example.org", "Soporte");
        StubLookup stub = new StubLookup(Optional.of(u));
        coordinator = new IngestionCoordinator(store, stub, 8, 1);
        coordinator.submit(alert("agarcia"));
        waitFor(store, 1);
        EventStore.Entry e = store.snapshot().get(0);
        assertEquals(IngestionCoordinator.LDAP_FOUND, e.ldapStatus());
        assertNotNull(e.user());
        assertEquals("agarcia", e.user().username());
    }

    @Test
    void lookupAusenteMarcaMissing() throws Exception {
        EventStore store = new EventStore(16);
        StubLookup stub = new StubLookup(Optional.empty());
        coordinator = new IngestionCoordinator(store, stub, 8, 1);
        coordinator.submit(alert("noexiste"));
        waitFor(store, 1);
        EventStore.Entry e = store.snapshot().get(0);
        assertEquals(IngestionCoordinator.LDAP_MISSING, e.ldapStatus());
        assertNull(e.user());
    }

    @Test
    void lookupConErrorMarcaErrorSinDetalle() throws Exception {
        EventStore store = new EventStore(16);
        StubLookupWithError stub = new StubLookupWithError(new RuntimeException("credenciales secretas/internas"));
        coordinator = new IngestionCoordinator(store, stub, 8, 1);
        coordinator.submit(alert("jlopez"));
        waitFor(store, 1);
        EventStore.Entry e = store.snapshot().get(0);
        assertEquals(IngestionCoordinator.LDAP_ERROR, e.ldapStatus());
        assertNull(e.user());
        String snapshot = store.snapshot().toString();
        assertEquals(false, snapshot.contains("credenciales secretas"),
                "El snapshot no debe contener la causa del error");
    }

    @Test
    void concurrenteDedupYConteo() throws Exception {
        EventStore store = new EventStore(64);
        StubLookup stub = new StubLookup(Optional.empty());
        coordinator = new IngestionCoordinator(store, stub, 32, 4);
        Alert mismoId = alert("agarcia");
        for (int i = 0; i < 20; i++) coordinator.submit(mismoId);
        for (int i = 0; i < 20; i++) coordinator.submit(alert("user" + i));
        waitFor(store, 21);
        assertEquals(21, store.size(),
                "EventStore debe deduplicar por id: 1 + 20 únicos = 21, fue " + store.size());
        assertEquals(0, coordinator.rejectedCount());
    }

    private static void waitFor(EventStore store, int expected) throws InterruptedException {
        long deadline = System.nanoTime() + 2_000_000_000L;
        while (store.size() < expected && System.nanoTime() < deadline) {
            Thread.sleep(20);
        }
    }

    private static final class StubLookup implements DirectoryLookup {
        final Optional<DirectoryUser> result;
        final java.util.concurrent.atomic.AtomicInteger calls = new java.util.concurrent.atomic.AtomicInteger();

        StubLookup(Optional<DirectoryUser> result) {
            this.result = result;
        }

        @Override
        public Optional<DirectoryUser> find(String username) {
            calls.incrementAndGet();
            return result;
        }

        @Override public void close() {}
    }

    private static final class StubLookupWithError implements DirectoryLookup {
        private final RuntimeException toThrow;
        StubLookupWithError(RuntimeException t) { this.toThrow = t; }
        @Override public Optional<DirectoryUser> find(String username) { throw toThrow; }
        @Override public void close() {}
    }
}