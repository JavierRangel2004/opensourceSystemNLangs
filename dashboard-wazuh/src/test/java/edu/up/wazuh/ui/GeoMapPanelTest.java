package edu.up.wazuh.ui;

import edu.up.wazuh.model.Alert;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;
import java.awt.Dimension;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Pruebas de comportamiento observable del {@link GeoMapPanel}.
 *
 * <p>Cada test sitúa coordenadas conocidas y verifica conteos, agregación y
 * comportamiento del tooltip sobre la base Natural Earth. No se inspecciona
 * estado privado.</p>
 */
class GeoMapPanelTest {

    @Test
    @DisplayName("Coordenadas nulas se cuentan aparte; las válidas forman un símbolo")
    void nullCoordinatesAreDropped() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            GeoMapPanel panel = new GeoMapPanel();
            List<Alert> alerts = new ArrayList<>();
            alerts.add(alert("a1", 19.4326, -99.1332, 5));
            alerts.add(alert("a2", null, null, 7));
            alerts.add(alert("a3", null, null, 4));
            panel.updateAlerts(alerts);
            assertEquals(1, panel.symbolCount());
            assertEquals(2, panel.noLocationCount());
        });
    }

    @Test
    @DisplayName("Natural Earth carga contornos: polígonos cubren Ciudad de México")
    void naturalEarthCoversMexicoCity() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            GeoMapPanel panel = new GeoMapPanel();
            List<NaturalEarthMap.PolygonGeometry> polys = panel.polygonsForTest();
            // El punto (19.4326, -99.1332) cae dentro de México según Natural Earth.
            assertTrue(coversAny(polys, 19.4326, -99.1332),
                    "Algún polígono de Natural Earth debe cubrir Ciudad de México");
        });
    }

    @Test
    @DisplayName("Agregación: dos alertas cercanas en CDMX forman un símbolo de count=2")
    void aggregationAtSameLocation() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            GeoMapPanel panel = new GeoMapPanel();
            List<Alert> alerts = new ArrayList<>();
            alerts.add(alert("a1", 19.431, -99.131, 3));
            alerts.add(alert("a2", 19.432, -99.132, 5));
            alerts.add(alert("a3", 19.44, -99.15, 7));
            panel.updateAlerts(alerts);
            assertEquals(2, panel.symbolCount());
            GeoMapPanel.MapSymbol biggest = null;
            for (GeoMapPanel.MapSymbol s : panel.symbols()) {
                if (biggest == null || s.count() > biggest.count()) {
                    biggest = s;
                }
            }
            assertNotNull(biggest);
            assertEquals(2, biggest.count());
            assertEquals(5, biggest.maxLevel());
        });
    }

    @Test
    @DisplayName("Sin alertas: cero símbolos y cero en no-ubicación")
    void noAlertsClearsState() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            GeoMapPanel panel = new GeoMapPanel();
            panel.updateAlerts(List.of(alert("located", 19.4326, -99.1332, 5),
                    alert("unknown", null, null, 7)));
            panel.updateAlerts(List.of());
            assertEquals(0, panel.symbolCount());
            assertEquals(0, panel.noLocationCount());
        });
    }

    @Test
    void wideCanvasPreservesGeographicScaleAndCentersWorld() {
        MapProjection projection = new MapProjection(new Dimension(900, 180));
        var center = projection.projectRaw(0, 0);
        var east = projection.projectRaw(0, 10);
        var north = projection.projectRaw(10, 0);
        assertEquals(450.0, center.x, 0.000001);
        assertEquals(90.0, center.y, 0.000001);
        assertEquals(east.x - center.x, center.y - north.y, 0.000001);
        assertEquals(270.0, projection.projectRaw(0, -180).x, 0.000001);
        assertEquals((int) Math.round(east.x), projection.project(0, 10).pixelX());
        assertEquals((int) Math.round(north.y), projection.project(10, 0).pixelY());
    }

    /**
     * Punto-en-polígono por ray-casting. Comprueba que al menos un polígono
     * de Natural Earth contiene la coordenada (lat, lon).
     */
    private static boolean coversAny(List<NaturalEarthMap.PolygonGeometry> polys,
                                     double lat, double lon) {
        for (NaturalEarthMap.PolygonGeometry p : polys) {
            if (pointInRing(p.ring(), lat, lon)) {
                return true;
            }
        }
        return false;
    }

    private static boolean pointInRing(double[][] ring, double lat, double lon) {
        if (ring == null || ring.length < 3) {
            return false;
        }
        boolean inside = false;
        int n = ring.length;
        for (int i = 0, j = n - 1; i < n; j = i++) {
            double xi = ring[i][0], yi = ring[i][1];
            double xj = ring[j][0], yj = ring[j][1];
            boolean intersect = ((yi > lat) != (yj > lat))
                    && (lon < (xj - xi) * (lat - yi) / ((yj - yi) + 0.0) + xi);
            if (intersect) {
                inside = !inside;
            }
        }
        return inside;
    }

    private static Alert alert(String id, Double lat, Double lon, int level) {
        return new Alert(id, Instant.parse("2026-10-13T10:00:00Z"),
                "001", "agent-A", "r1", level, "desc", "", "",
                lat, lon, "custom-dashboard");
    }
}