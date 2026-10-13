package edu.up.wazuh.events;

import edu.up.wazuh.model.Agent;
import edu.up.wazuh.model.Alert;
import edu.up.wazuh.model.DirectoryUser;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EventStoreTest {

    @Test
    void deduplicates_by_id() {
        EventStore store = new EventStore(8);
        Alert a = alert("dup-1", "rule-1");
        assertTrue(store.add(a, user("dup-1"), "found"));
        assertFalse(store.add(a, user("dup-1"), "found-again"));
        assertEquals(1, store.size());
    }

    @Test
    void evicts_oldest_FIFO_when_full() {
        EventStore store = new EventStore(2);
        assertTrue(store.add(alert("a-1", "r-1"), null, ""));
        assertTrue(store.add(alert("a-2", "r-2"), null, ""));
        assertTrue(store.add(alert("a-3", "r-3"), null, ""));

        List<EventStore.Entry> snap = store.snapshot();
        assertEquals(2, snap.size());
        assertEquals("a-2", snap.get(0).alert().id());
        assertEquals("a-3", snap.get(1).alert().id());
    }

    @Test
    void re_inserts_after_eviction_once_id_no_longer_present() {
        EventStore store = new EventStore(1);
        assertTrue(store.add(alert("a-1", "r-1"), null, ""));
        assertTrue(store.add(alert("a-2", "r-2"), null, ""));
        // a-1 evicted; re-insert should succeed.
        assertTrue(store.add(alert("a-1", "r-1"), null, ""));
        assertEquals("a-1", store.snapshot().get(0).alert().id());
    }

    @Test
    void snapshot_is_immutable() {
        EventStore store = new EventStore(4);
        store.add(alert("a-1", "r-1"), null, "");
        List<EventStore.Entry> snap = store.snapshot();
        assertThrows(UnsupportedOperationException.class,
                () -> snap.add(new EventStore.Entry(alert("x", "r"), null, "")));
        assertThrows(UnsupportedOperationException.class, () -> snap.clear());
    }

    @Test
    void snapshot_independent_of_store_mutations() {
        EventStore store = new EventStore(4);
        store.add(alert("a-1", "r-1"), null, "");
        List<EventStore.Entry> before = store.snapshot();
        store.add(alert("a-2", "r-2"), null, "");
        assertEquals(1, before.size(), "snapshot must not reflect later changes");
    }

    @Test
    void rejects_non_positive_capacity() {
        assertThrows(IllegalArgumentException.class, () -> new EventStore(0));
        assertThrows(IllegalArgumentException.class, () -> new EventStore(-1));
    }

    @Test
    void rejects_missing_alert_and_blank_id() {
        EventStore store = new EventStore(2);
        assertThrows(IllegalArgumentException.class,
                () -> store.add(null, null, ""));
        Alert blank = new Alert("", Instant.now(), "", "", "r", 5, "", "", "",
                null, null, "");
        assertThrows(IllegalArgumentException.class,
                () -> store.add(blank, null, ""));
    }

    @Test
    void thread_safe_under_concurrent_inserts() throws Exception {
        EventStore store = new EventStore(5000);
        int threads = 16;
        int insertsPerThread = 250;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger ok = new AtomicInteger();
        AtomicInteger dup = new AtomicInteger();
        for (int t = 0; t < threads; t++) {
            int tid = t;
            pool.submit(() -> {
                start.await();
                for (int i = 0; i < insertsPerThread; i++) {
                    Alert a = alert("t" + tid + "-" + i, "rule-" + i);
                    if (store.add(a, null, "ok")) ok.incrementAndGet();
                    else dup.incrementAndGet();
                }
                return null;
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(20, TimeUnit.SECONDS));
        assertEquals(threads * insertsPerThread, ok.get() + dup.get(),
                "every insert should report success or duplicate");
        assertEquals(ok.get(), store.size(), "no losses, no duplicates counted");
    }

    @Test
    void concurrent_dedup_converges_to_unique_count() throws Exception {
        EventStore store = new EventStore(100);
        int threads = 8;
        int perThread = 100;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        for (int t = 0; t < threads; t++) {
            pool.submit(() -> {
                start.await();
                for (int i = 0; i < perThread; i++) {
                    store.add(alert("shared-id", "r-1"), null, "");
                }
                return null;
            });
        }
        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(20, TimeUnit.SECONDS));
        assertEquals(1, store.size());
    }

    @Test
    void entry_preserves_user_and_ldap_status() {
        EventStore store = new EventStore(2);
        DirectoryUser u = new DirectoryUser("alice", "Alice", "alice@up.ac.pa", "IT");
        assertTrue(store.add(alert("a-1", "r-1"), u, "found"));
        EventStore.Entry e = store.snapshot().get(0);
        assertNotNull(e.user());
        assertEquals("alice", e.user().username());
        assertEquals("found", e.ldapStatus());
    }

    private static Alert alert(String id, String ruleId) {
        return new Alert(id, Instant.parse("2024-09-23T14:28:51Z"),
                "agent-1", "host1", ruleId, 5, "", "", "",
                null, null, "");
    }

    private static DirectoryUser user(String name) {
        return new DirectoryUser(name, name, name + "@up.ac.pa", "IT");
    }

    @SuppressWarnings("unused")
    private static Agent agent(String id) {
        return new Agent(id, "host", "active", "127.0.0.1", "Linux");
    }
}
