package edu.up.wazuh.app;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import edu.up.wazuh.events.AlertParser;
import edu.up.wazuh.events.EventStore;
import edu.up.wazuh.model.Alert;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Carga alertas de muestra desde el classpath para el modo demo.
 *
 * <p>Cada alerta lleva un campo auxiliar {@code _minutes_ago}; al cargar se
 * calcula un {@code Instant} base y se asigna
 * {@code timestamp = base.minus(_minutes_ago)}. Esto coloca las doce alertas
 * dentro de la última hora para que los filtros temporales y las gráficas
 * tengan datos visibles al presentar.</p>
 *
 * <p>Sólo se aplica en modo {@code --demo}. Las alertas del modo {@code --live}
 * llegan por el webhook con sus marcas de tiempo reales y no se modifican.</p>
 */
public final class DemoDataLoader {

    public static final String DEMO_BANNER = "MUESTRA";
    public static final String DEMO_DIRECTORY_LABEL = "directory-demo";
    private static final Duration REBASE_WAIT = Duration.ofSeconds(5);

    private DemoDataLoader() {}

    /**
     * Lee el recurso demo del classpath, calcula la marca de tiempo relativa
     * para cada alerta, las entrega al coordinador (o al store directamente
     * si no hay coordinador) y espera bloqueante hasta que el store contenga
     * exactamente las {@code N} alertas.
     *
     * <p>Lanza {@link IllegalStateException} si la cola del coordinador está
     * saturada (no se cae al store directo para no simular un resultado que
     * no ocurrió).</p>
     */
    public static List<Alert> loadAndIngest(String resourcePath, EventStore store,
                                            IngestionCoordinator coordinator)
            throws IOException, InterruptedException {
        Objects.requireNonNull(resourcePath, "resourcePath");
        Objects.requireNonNull(store, "store");
        InputStream in = DemoDataLoader.class.getClassLoader().getResourceAsStream(resourcePath);
        if (in == null) {
            throw new IOException("Recurso demo no encontrado: " + resourcePath);
        }
        try (InputStreamReader reader = new InputStreamReader(in, StandardCharsets.UTF_8)) {
            JsonElement root = JsonParser.parseReader(reader);
            JsonArray arr;
            if (root.isJsonArray()) {
                arr = root.getAsJsonArray();
            } else if (root.isJsonObject() && root.getAsJsonObject().has("alerts")) {
                arr = root.getAsJsonObject().getAsJsonArray("alerts");
            } else {
                throw new IOException("Formato demo inválido: raíz debe ser arreglo o {\"alerts\":[...]}");
            }

            Instant base = Instant.now();
            AlertParser parser = new AlertParser();
            List<Alert> rebased = new ArrayList<>(arr.size());

            for (JsonElement el : arr) {
                JsonObject obj = el.getAsJsonObject();
                long minutesAgo = extractMinutesAgo(obj);
                Instant ts = base.minus(Duration.ofMinutes(minutesAgo));
                obj.addProperty("timestamp", ts.toString());
                Alert a = parser.parse(obj.toString());
                rebased.add(a);

                if (coordinator != null) {
                    if (!coordinator.submit(a)) {
                        throw new IllegalStateException(
                                "Demo: cola de ingesta saturada al enviar " + a.id()
                                        + " (rejected=" + (coordinator.rejectedCount())
                                        + "). No se hace store.add directo: la alerta se perdió.");
                    }
                } else {
                    store.add(a, null, IngestionCoordinator.LDAP_NOT_CONFIGURED);
                }
            }

            if (coordinator != null) {
                awaitSize(store, rebased.size(), REBASE_WAIT);
            }
            return rebased;
        }
    }

    private static long extractMinutesAgo(JsonObject obj) {
        if (!obj.has("_minutes_ago")) {
            throw new IllegalArgumentException("Demo: alerta sin _minutes_ago");
        }
        long v = obj.get("_minutes_ago").getAsLong();
        if (v < 0 || v > 60) {
            throw new IllegalArgumentException("Demo: _minutes_ago fuera de 0..60: " + v);
        }
        return v;
    }

    private static void awaitSize(EventStore store, int expected, Duration max)
            throws InterruptedException {
        long deadline = System.nanoTime() + max.toNanos();
        while (store.size() < expected && System.nanoTime() < deadline) {
            Thread.sleep(20);
        }
        if (store.size() < expected) {
            throw new IllegalStateException("Demo: solo " + store.size() + " de "
                    + expected + " alertas ingestadas antes del plazo");
        }
    }
}