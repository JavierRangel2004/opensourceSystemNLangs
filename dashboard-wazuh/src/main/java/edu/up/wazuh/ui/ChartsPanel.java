package edu.up.wazuh.ui;

import edu.up.wazuh.model.Alert;

import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.axis.DateAxis;
import org.jfree.chart.plot.XYPlot;
import org.jfree.chart.renderer.xy.XYLineAndShapeRenderer;
import org.jfree.data.category.DefaultCategoryDataset;
import org.jfree.data.time.Hour;
import org.jfree.data.time.TimeSeries;
import org.jfree.data.time.TimeSeriesCollection;

import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

/**
 * Panel con las tres gráficas JFreeChart del dashboard:
 *
 * <ol>
 *   <li>Barras de las N reglas con mayor número de alertas.</li>
 *   <li>Barras de severidad agrupada por tramos (0-2, 3-5, 6-9, 10-12, 13-15).</li>
 *   <li>Serie temporal por hora en UTC, con documentación visible sobre el huso.</li>
 * </ol>
 *
 * <p>Las tres gráficas consumen exactamente el mismo subset de eventos que el
 * resto del panel; esto se garantiza aceptando la lista filtrada desde
 * {@link DashboardPanel} y manteniéndola en memoria hasta el próximo refresh.</p>
 *
 * <p>Toda actualización se programa en el EDT; las llamadas externas deben
 * hacerse a través de {@link #updateAlerts(List, Instant, Instant)} y no
 * invocarse desde un hilo de I/O.</p>
 */
public final class ChartsPanel extends JPanel {

    private static final int TOP_RULES = 8;

    private final DefaultCategoryDataset rulesDataset = new DefaultCategoryDataset();
    private final DefaultCategoryDataset severityDataset = new DefaultCategoryDataset();
    private final TimeSeriesCollection timeDataset = new TimeSeriesCollection();
    private final TimeSeries timeSeries = new TimeSeries("Eventos por hora");
    private final JFreeChart rulesChart;
    private final JFreeChart severityChart;
    private final JFreeChart timeChart;
    private final ChartPanel rulesPanel;
    private final ChartPanel severityPanel;
    private final ChartPanel timePanel;

    public ChartsPanel() {
        super(new BorderLayout());
        rulesChart = ChartFactory.createBarChart(
                "Top reglas",
                "Regla",
                "Eventos",
                rulesDataset,
                org.jfree.chart.plot.PlotOrientation.HORIZONTAL,
                false, true, false);
        severityChart = ChartFactory.createBarChart(
                "Severidad (tramos Wazuh)",
                "Nivel",
                "Eventos",
                severityDataset,
                org.jfree.chart.plot.PlotOrientation.VERTICAL,
                false, true, false);
        timeDataset.addSeries(timeSeries);
        timeChart = ChartFactory.createTimeSeriesChart(
                "Eventos por hora (UTC)",
                "Hora UTC",
                "Eventos",
                timeDataset,
                false, true, false);

        // Forzar el eje X a usar la zona UTC para que la serie temporal refleje
        // explícitamente el huso horario, como pide el PLAN.
        XYPlot plot = (XYPlot) timeChart.getPlot();
        DateAxis axis = (DateAxis) plot.getDomainAxis();
        axis.setTimeZone(java.util.TimeZone.getTimeZone("UTC"));
        XYLineAndShapeRenderer renderer = new XYLineAndShapeRenderer(true, true);
        plot.setRenderer(renderer);

        rulesPanel = new ChartPanel(rulesChart);
        severityPanel = new ChartPanel(severityChart);
        timePanel = new ChartPanel(timeChart);

        rulesPanel.setPreferredSize(new Dimension(560, 280));
        severityPanel.setPreferredSize(new Dimension(560, 280));
        timePanel.setPreferredSize(new Dimension(560, 280));

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Reglas", rulesPanel);
        tabs.addTab("Severidad", severityPanel);
        tabs.addTab("Serie temporal (UTC)", timePanel);
        add(tabs, BorderLayout.CENTER);
    }

    /**
     * Reemplaza los datos de las tres gráficas. Pensado para uso en EDT; si se
     * invoca desde otro hilo, programa la actualización en el EDT para evitar
     * condiciones de carrera con JFreeChart.
     */
    public void updateAlerts(List<Alert> alerts, Instant from, Instant to) {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(() -> updateAlerts(alerts, from, to));
            return;
        }
        rulesDataset.clear();
        severityDataset.clear();
        timeSeries.clear();

        if (alerts == null || alerts.isEmpty()) {
            return;
        }

        Map<String, Integer> ruleCounts = new TreeMap<>();
        int[] buckets = new int[5]; // 0-2, 3-5, 6-9, 10-12, 13-15
        Map<Hour, Integer> hourly = new TreeMap<>(Comparator.comparingLong(Hour::getSerialIndex));

        for (Alert a : alerts) {
            String rule = a.ruleId() == null || a.ruleId().isEmpty() ? "(sin regla)" : a.ruleId();
            ruleCounts.merge(rule, 1, Integer::sum);

            int lvl = a.level();
            int idx;
            if (lvl <= 2) idx = 0;
            else if (lvl <= 5) idx = 1;
            else if (lvl <= 9) idx = 2;
            else if (lvl <= 12) idx = 3;
            else idx = 4;
            buckets[idx]++;

            Instant t = a.timestamp();
            if (t != null) {
                // Construir el Hour con la zona UTC explícita: el eje X está
                // forzado a UTC, así que la clave de bucket debe coincidir
                // exactamente con ese huso o las fechas aparecen desplazadas.
                Hour hour = new Hour(java.util.Date.from(t),
                        java.util.TimeZone.getTimeZone("UTC"), Locale.ROOT);
                hourly.merge(hour, 1, Integer::sum);
            }
        }

        // Top N reglas: ordenar descendente y conservar el orden estable.
        List<Map.Entry<String, Integer>> sorted = new ArrayList<>(ruleCounts.entrySet());
        sorted.sort(Map.Entry.<String, Integer>comparingByValue().reversed());
        int emitted = 0;
        Map<String, Integer> topRules = new LinkedHashMap<>();
        for (Map.Entry<String, Integer> e : sorted) {
            if (emitted >= TOP_RULES) {
                break;
            }
            topRules.put(e.getKey(), e.getValue());
            emitted++;
        }
        for (Map.Entry<String, Integer> e : topRules.entrySet()) {
            rulesDataset.addValue(e.getValue(), "Eventos", e.getKey());
        }

        String[] labels = {"0-2", "3-5", "6-9", "10-12", "13-15"};
        for (int i = 0; i < buckets.length; i++) {
            severityDataset.addValue(buckets[i], "Eventos", labels[i]);
        }

        for (Map.Entry<Hour, Integer> e : hourly.entrySet()) {
            timeSeries.add(e.getKey(), e.getValue());
        }

        // Anotación textual sobre el rango UTC. Cuando el periodo es "Todo"
// (from == null) usamos el título base sin rango para evitar inducir al
// usuario sobre una ventana que en realidad no existe.
        if (from == null || to == null) {
            timeChart.setTitle("Eventos por hora (UTC)");
        } else {
            long hours = java.time.Duration.between(from, to).toHours();
            timeChart.setTitle(String.format(Locale.ROOT,
                    "Eventos por hora (UTC) - %s a %s (%dh)",
                    from, to, hours));
        }
    }

    /** Acceso a las gráficas para exportación/tests. */
    public JFreeChart rulesChart() {
        return rulesChart;
    }

    public JFreeChart severityChart() {
        return severityChart;
    }

    public JFreeChart timeChart() {
        return timeChart;
    }
}