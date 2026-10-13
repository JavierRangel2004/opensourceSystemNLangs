package edu.up.wazuh.ui;

import edu.up.wazuh.events.EventStore;
import edu.up.wazuh.model.Agent;
import edu.up.wazuh.model.Alert;
import edu.up.wazuh.model.DirectoryUser;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.swing.JSpinner;
import javax.swing.SwingUtilities;
import java.lang.reflect.InvocationTargetException;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pruebas de comportamiento observable de {@link DashboardPanel}.
 *
 * <p>Cada test modifica un control del panel y verifica el estado de las
 * vistas (KPI, tabla, mapa, gráficas, detalle). Las pruebas no inspeccionan
 * atributos privados ni la composición interna: sólo el resultado visible.</p>
 */
class DashboardPanelTest {

    private static <T> T runOnEdt(java.util.concurrent.Callable<T> task) throws Exception {
        AtomicReference<T> ref = new AtomicReference<>();
        AtomicReference<Throwable> err = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> {
            try {
                ref.set(task.call());
            } catch (Throwable t) {
                err.set(t);
            }
        });
        if (err.get() != null) {
            Throwable t = err.get();
            if (t instanceof Exception) {
                throw (Exception) t;
            }
            throw new InvocationTargetException(t);
        }
        return ref.get();
    }

    /** Construye una alerta determinista con timestamp variable. */
    private static Alert mk(String id, Instant ts, String agentId, String agentName,
                            String ruleId, int level, String description,
                            Double lat, Double lon) {
        return new Alert(id, ts, agentId, agentName, ruleId, level,
                description, "", "", lat, lon, "custom-dashboard");
    }

    /** Encuentra el JSpinner dentro del FiltersPanel. */
    private static JSpinner findSpinner(FiltersPanel panel) {
        for (java.awt.Component c : panel.getComponents()) {
            JSpinner found = findSpinnerRecursive(c);
            if (found != null) {
                return found;
            }
        }
        return null;
    }

    private static JSpinner findSpinnerRecursive(java.awt.Component c) {
        if (c instanceof JSpinner) {
            return (JSpinner) c;
        }
        if (c instanceof java.awt.Container) {
            for (java.awt.Component child : ((java.awt.Container) c).getComponents()) {
                JSpinner found = findSpinnerRecursive(child);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    @Test
    @DisplayName("El estado inicial del filtro refleja 'Última 1h' con ventana móvil")
    void initialStateUsesPeriodWindow() throws Exception {
        runOnEdt(() -> {
            EventStore store = new EventStore(8);
            DashboardPanel panel = new DashboardPanel(store, true);
            FiltersPanel.FilterState s = panel.filtersPanel().currentState();
            Instant now = Instant.now();
            assertNotNull(s.from);
            assertNotNull(s.to);
            // La ventana cubre aproximadamente la última hora.
            long seconds = java.time.Duration.between(s.from, s.to).getSeconds();
            assertTrue(Math.abs(seconds - 3600) <= 5,
                    "Ventana esperada ~3600s, fue " + seconds);
            // 'to' coincide aproximadamente con 'now'.
            long drift = Math.abs(java.time.Duration.between(now, s.to).getSeconds());
            assertTrue(drift <= 5, "Drift to-now esperado <=5s, fue " + drift);
            return null;
        });
    }

    @Test
    @DisplayName("Filtro de nivel mínimo (control) reduce tabla, mapa, KPI y detalle")
    void levelFilterPropagatesAcrossViews() throws Exception {
        runOnEdt(() -> {
            EventStore store = new EventStore(16);
            store.add(mk("a1", Instant.now(), "001", "ag", "r1", 3,
                    "low", 19.43, -99.13), null, "");
            store.add(mk("a2", Instant.now(), "002", "ag", "r2", 12,
                    "high", 19.45, -99.10), null, "");
            DashboardPanel panel = new DashboardPanel(store, true);

            // Pre-filtro: ambos eventos visibles.
            assertEquals(2, panel.eventTablePanel().entryCount());
            assertEquals("2", panel.kpiPanel().total());
            assertEquals("1", panel.kpiPanel().highSeverity());

            // Subir nivel mínimo a 10.
            JSpinner spinner = findSpinner(panel.filtersPanel());
            spinner.setValue(10);
            panel.refresh();

            assertEquals(1, panel.eventTablePanel().entryCount());
            assertEquals("1", panel.kpiPanel().total());
            assertEquals("1", panel.kpiPanel().highSeverity());
            assertEquals(1, panel.geoMapPanel().symbolCount());
            return null;
        });
    }

    @Test
    @DisplayName("Filtro de periodo: excluye eventos fuera de la ventana móvil")
    void periodFilterExcludesOldEvents() throws Exception {
        runOnEdt(() -> {
            EventStore store = new EventStore(16);
            Instant now = Instant.now();
            store.add(mk("recent", now.minusSeconds(60),
                    "001", "ag", "r1", 5, "ok", 19.43, -99.13), null, "");
            store.add(mk("old", now.minusSeconds(7200),
                    "001", "ag", "r1", 5, "ok", 19.43, -99.13), null, "");
            DashboardPanel panel = new DashboardPanel(store, true);

            // Periodo por defecto: última 1h -> sólo 'recent'.
            panel.refresh();
            assertEquals(1, panel.eventTablePanel().entryCount());
            assertEquals("1", panel.kpiPanel().total());

            // Cambiar a "Últimas 6h" (índice 1).
            javax.swing.JComboBox<?> period = findPeriodCombo(panel.filtersPanel());
            period.setSelectedIndex(1);
            panel.refresh();
            assertEquals(2, panel.eventTablePanel().entryCount());

            // Cambiar a "Todo".
            period.setSelectedIndex(4);
            panel.refresh();
            assertEquals(2, panel.eventTablePanel().entryCount());
            return null;
        });
    }

    @Test
    @DisplayName("El periodo se evalúa como ventana móvil: tras avance del reloj, eventos nuevos entran")
    void periodWindowIsMoving() throws Exception {
        runOnEdt(() -> {
            EventStore store = new EventStore(8);
            DashboardPanel panel = new DashboardPanel(store, true);

            // Inyectar evento "viejo" (hace 2h) y refrescar.
            store.add(mk("old", Instant.now().minusSeconds(7200),
                    "001", "ag", "r1", 5, "ok", null, null), null, "");
            panel.refresh();
            assertEquals(0, panel.eventTablePanel().entryCount());

            // Inyectar evento "reciente" y refrescar: ahora entra.
            store.add(mk("new", Instant.now().minusSeconds(60),
                    "002", "ag", "r1", 5, "ok", null, null), null, "");
            panel.refresh();
            assertEquals(1, panel.eventTablePanel().entryCount());
            return null;
        });
    }

    @Test
    @DisplayName("Conteo de mapa: símbolos = buckets geográficos únicos")
    void mapSymbolCountMatchesUniqueLocations() throws Exception {
        runOnEdt(() -> {
            EventStore store = new EventStore(8);
            store.add(mk("a", Instant.now(), "001", "ag", "r1", 5,
                    "x", 19.43, -99.13), null, "");
            store.add(mk("b", Instant.now(), "002", "ag", "r1", 5,
                    "x", 19.43, -99.13), null, "");
            store.add(mk("c", Instant.now(), "003", "ag", "r1", 5,
                    "x", 19.44, -99.15), null, "");
            DashboardPanel panel = new DashboardPanel(store, true);
            panel.refresh();
            assertEquals(2, panel.geoMapPanel().symbolCount());
            assertEquals(0, panel.geoMapPanel().noLocationCount());
            return null;
        });
    }

    @Test
    @DisplayName("Mapa: dibuja polígonos cuando el GeoJSON está disponible")
    void mapDrawsPolygonsWhenGeoJsonAvailable() throws Exception {
        runOnEdt(() -> {
            GeoMapPanel map = new GeoMapPanel();
            NaturalEarthMap base = GlobalNaturalEarth.get();
            // El número de polígonos coincide con la carga del país.
            assertEquals(base.polygons().size(), map.polygonsForTest().size());
            return null;
        });
    }

    @Test
    @DisplayName("Filtro de agente: ids no presentes descartan eventos")
    void agentFilterById() throws Exception {
        runOnEdt(() -> {
            EventStore store = new EventStore(8);
            store.add(mk("a", Instant.now(), "001", "ag", "r1", 5,
                    "x", null, null), null, "");
            store.add(mk("b", Instant.now(), "002", "ag", "r1", 5,
                    "x", null, null), null, "");
            DashboardPanel panel = new DashboardPanel(store, true);
            // Asegurar que el filtro de agente conoce al 002.
            panel.setAgents(List.of(
                    new Agent("002", "agent-B", "Active", "", "")));
            panel.refresh();
            assertEquals(2, panel.eventTablePanel().entryCount());
            javax.swing.JComboBox<?> combo = findAgentCombo(panel.filtersPanel());
            // Selecciona el AgentOption cuyo id == "002" (estable, no por índice).
            int target = findAgentOptionById(combo, "002");
            assertTrue(target >= 0, "El combo debe contener al agente 002");
            combo.setSelectedIndex(target);
            panel.refresh();
            assertEquals(1, panel.eventTablePanel().entryCount());
            return null;
        });
    }

    @Test
    @DisplayName("Detalle LDAP 'found' muestra nombre, email y departamento")
    void detailShowsFoundUser() throws Exception {
        runOnEdt(() -> {
            EventStore store = new EventStore(8);
            DashboardPanel panel = new DashboardPanel(store, true);
            EventStore.Entry entry = new EventStore.Entry(
                    mk("a", Instant.now(), "001", "ag", "r1", 5,
                            "x", null, null),
                    new DirectoryUser("jramirez", "Javier Ramirez",
                            "jramirez@up.ac.pa", "TI"),
                    "found");
            panel.detailPanel().showEntry(entry);
            String text = panel.detailPanel().text();
            assertTrue(text.contains("jramirez"));
            assertTrue(text.contains("Javier Ramirez"));
            assertTrue(text.contains("jramirez@up.ac.pa"));
            assertTrue(text.contains("TI"));
            return null;
        });
    }

    @Test
    @DisplayName("Detalle LDAP 'missing' avisa resultado vacío")
    void detailShowsMissing() throws Exception {
        runOnEdt(() -> {
            EventStore store = new EventStore(8);
            DashboardPanel panel = new DashboardPanel(store, true);
            EventStore.Entry entry = new EventStore.Entry(
                    mk("a", Instant.now(), "001", "ag", "r1", 5,
                            "x", null, null), null, "missing");
            panel.detailPanel().showEntry(entry);
            String text = panel.detailPanel().text();
            assertTrue(text.toLowerCase().contains("vacio")
                    || text.toLowerCase().contains("resultado"),
                    "Detalle LDAP 'missing' debe hablar de resultado vacío: " + text);
            return null;
        });
    }

    @Test
    @DisplayName("Detalle LDAP 'error' muestra mensaje de error sin filtrar detalle")
    void detailShowsError() throws Exception {
        runOnEdt(() -> {
            EventStore store = new EventStore(8);
            DashboardPanel panel = new DashboardPanel(store, true);
            EventStore.Entry entry = new EventStore.Entry(
                    mk("a", Instant.now(), "001", "ag", "r1", 5,
                            "x", null, null), null, "error");
            panel.detailPanel().showEntry(entry);
            String text = panel.detailPanel().text();
            assertTrue(text.toLowerCase().contains("error"),
                    "Detalle LDAP 'error' debe hablar de error: " + text);
            return null;
        });
    }

    @Test
    @DisplayName("Selección de tabla: se preserva tras refresh si el id sigue presente")
    void tableSelectionPreservedAcrossRefresh() throws Exception {
        runOnEdt(() -> {
            EventStore store = new EventStore(8);
            store.add(mk("p1", Instant.now(), "001", "ag", "r1", 5,
                    "x", 19.43, -99.13), null, "");
            store.add(mk("p2", Instant.now(), "002", "ag", "r2", 5,
                    "y", 19.45, -99.10), null, "");
            DashboardPanel panel = new DashboardPanel(store, true);
            panel.eventTablePanel().setSelectedIndexForTest(1);
            AtomicInteger notifications = new AtomicInteger();
            panel.eventTablePanel().addEntryListener(entry -> notifications.incrementAndGet());
            panel.refresh();
            assertEquals(0, notifications.get());
            EventStore.Entry sel = panel.eventTablePanel().selectedEntry();
            assertNotNull(sel);
            assertEquals("p2", sel.alert().id());
            return null;
        });
    }

    @Test
    @DisplayName("Selección de tabla: se limpia si el id desaparece del subset")
    void tableSelectionClearsWhenEntryFilteredOut() throws Exception {
        runOnEdt(() -> {
            EventStore store = new EventStore(8);
            store.add(mk("keep", Instant.now(), "001", "ag", "r1", 5,
                    "x", null, null), null, "");
            store.add(mk("drop", Instant.now(), "002", "ag", "r1", 12,
                    "y", null, null), null, "");
            DashboardPanel panel = new DashboardPanel(store, true);
            panel.eventTablePanel().setSelectedIndexForTest(0);
            JSpinner spinner = findSpinner(panel.filtersPanel());
            spinner.setValue(10);
            panel.refresh();
            assertEquals(1, panel.eventTablePanel().entryCount());
            assertEquals("drop", panel.eventTablePanel().entries().get(0).alert().id());
            assertNull(panel.eventTablePanel().selectedEntry());
            return null;
        });
    }

    /** Holder para no cargar el GeoJSON dos veces en el mismo test. */
    private static final class GlobalNaturalEarth {
        private static final NaturalEarthMap INSTANCE = NaturalEarthMap.loadDefault();
        static NaturalEarthMap get() { return INSTANCE; }
    }

    private static javax.swing.JComboBox<?> findPeriodCombo(FiltersPanel panel) {
        for (java.awt.Component c : panel.getComponents()) {
            javax.swing.JComboBox<?> found = findComboRecursive(c, "Última 1h");
            if (found != null) {
                return found;
            }
        }
        return null;
    }

    private static javax.swing.JComboBox<?> findAgentCombo(FiltersPanel panel) {
        for (java.awt.Component c : panel.getComponents()) {
            javax.swing.JComboBox<?> found = findComboRecursive(c, "(todos)");
            if (found != null) {
                return found;
            }
        }
        return null;
    }

    /**
     * Busca en el combo el AgentOption con id == target. -1 si no está.
     */
    private static int findAgentOptionById(javax.swing.JComboBox<?> combo, String target) {
        for (int i = 0; i < combo.getItemCount(); i++) {
            Object item = combo.getItemAt(i);
            if (item instanceof FiltersPanel.AgentOption
                    && target.equals(((FiltersPanel.AgentOption) item).id)) {
                return i;
            }
        }
        return -1;
    }

    private static javax.swing.JComboBox<?> findComboRecursive(java.awt.Component c, String firstLabel) {
        if (c instanceof javax.swing.JComboBox) {
            javax.swing.JComboBox<?> cb = (javax.swing.JComboBox<?>) c;
            if (cb.getItemCount() > 0) {
                Object first = cb.getItemAt(0);
                String label = first == null ? "" : first.toString();
                if (firstLabel.equals(label)) {
                    return cb;
                }
            }
        }
        if (c instanceof java.awt.Container) {
            for (java.awt.Component child : ((java.awt.Container) c).getComponents()) {
                javax.swing.JComboBox<?> found = findComboRecursive(child, firstLabel);
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }
}