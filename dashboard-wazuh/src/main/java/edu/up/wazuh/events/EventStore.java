package edu.up.wazuh.events;

import edu.up.wazuh.model.Alert;
import edu.up.wazuh.model.DirectoryUser;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Thread-safe, capacity-bounded FIFO store of normalized Wazuh events. Each
 * insertion is deduplicated by {@link Alert#id()}; duplicates return {@code
 * false} without altering the store. When the store reaches its capacity the
 * oldest entry is evicted to make room for the new one.
 *
 * <p>{@link #snapshot()} returns an unmodifiable view that callers can iterate
 * safely without further synchronization.
 */
public class EventStore {

    /** Stored entry: an alert plus the user lookup result and its status. */
    public record Entry(Alert alert, DirectoryUser user, String ldapStatus) {}

    private final int capacity;
    private final Deque<Entry> queue = new ArrayDeque<>();
    private final Set<String> ids = new HashSet<>();

    public EventStore(int capacity) {
        if (capacity <= 0) {
            throw new IllegalArgumentException("capacity must be > 0");
        }
        this.capacity = capacity;
    }

    /**
     * Adds the alert. Returns {@code true} when the alert was inserted;
     * {@code false} when an entry with the same id was already present (or is
     * still present after accounting for FIFO eviction).
     */
    public synchronized boolean add(Alert alert, DirectoryUser user, String ldapStatus) {
        if (alert == null) throw new IllegalArgumentException("alert required");
        String id = alert.id();
        if (id == null || id.isEmpty()) {
            throw new IllegalArgumentException("alert.id required");
        }
        if (ids.contains(id)) {
            return false;
        }
        while (queue.size() >= capacity) {
            Entry evicted = queue.pollFirst();
            if (evicted != null) {
                ids.remove(evicted.alert().id());
            }
        }
        queue.addLast(new Entry(alert, user, ldapStatus == null ? "" : ldapStatus));
        ids.add(id);
        return true;
    }

    /** Returns an immutable, ordered snapshot of the current entries. */
    public synchronized List<Entry> snapshot() {
        return List.copyOf(queue);
    }

    /** Returns the current entry count. */
    public synchronized int size() {
        return queue.size();
    }

    /** Returns the configured capacity. */
    public int capacity() {
        return capacity;
    }
}
