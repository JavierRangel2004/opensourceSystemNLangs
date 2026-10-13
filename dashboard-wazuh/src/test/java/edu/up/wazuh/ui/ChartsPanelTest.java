package edu.up.wazuh.ui;

import edu.up.wazuh.model.Alert;
import org.jfree.chart.axis.DateAxis;
import org.jfree.chart.plot.XYPlot;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.swing.SwingUtilities;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.TimeZone;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Pruebas de la serie temporal JFreeChart: los buckets deben caer en la
 * zona UTC independientemente de la zona por defecto de la JVM.
 */
class ChartsPanelTest {

    private TimeZone originalDefault;

    @BeforeEach
    void saveDefault() {
        originalDefault = TimeZone.getDefault();
    }

    @AfterEach
    void restoreDefault() {
        TimeZone.setDefault(originalDefault);
    }

    @Test
    @DisplayName("Hour buckets respetan UTC aunque la JVM esté en otra zona")
    void hourBucketsRespectUtcAcrossTimezones() throws Exception {
        TimeZone.setDefault(TimeZone.getTimeZone("Asia/Kolkata"));
        SwingUtilities.invokeAndWait(() -> {
            ChartsPanel panel = new ChartsPanel();
            List<Alert> alerts = new ArrayList<>();
            // Dos eventos en la misma hora UTC pero a distinta hora local.
            Instant t1 = LocalDateTime.of(2026, 10, 13, 2, 0)
                    .toInstant(ZoneOffset.UTC);
            Instant t2 = LocalDateTime.of(2026, 10, 13, 2, 30)
                    .toInstant(ZoneOffset.UTC);
            alerts.add(alert("a1", t1, 5));
            alerts.add(alert("a2", t2, 5));
            panel.updateAlerts(alerts,
                    LocalDateTime.of(2026, 10, 13, 1, 0).toInstant(ZoneOffset.UTC),
                    LocalDateTime.of(2026, 10, 13, 3, 0).toInstant(ZoneOffset.UTC));

            // El eje debe estar forzado a UTC.
            XYPlot plot = (XYPlot) panel.timeChart().getPlot();
            DateAxis axis = (DateAxis) plot.getDomainAxis();
            assertEquals(TimeZone.getTimeZone("UTC"), axis.getTimeZone());

            // Sólo debe haber un bucket con dos conteos.
            org.jfree.data.time.TimeSeriesCollection dataset =
                    (org.jfree.data.time.TimeSeriesCollection)
                            panel.timeChart().getXYPlot().getDataset();
            assertEquals(1, dataset.getSeriesCount());
            org.jfree.data.time.TimeSeries series = dataset.getSeries(0);
            assertEquals(1, series.getItemCount());
            assertEquals(2, series.getValue(0).intValue());
        });
    }


    private static Alert alert(String id, Instant ts, int level) {
        return new Alert(id, ts, "001", "ag", "r1", level,
                "x", "", "", null, null, "custom-dashboard");
    }
}