package edu.up.wazuh.ui;

import edu.up.wazuh.events.EventStore;
import edu.up.wazuh.model.Agent;
import edu.up.wazuh.model.Alert;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.Graphics2D;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.image.BufferedImage;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Panel principal del dashboard. Combina banner, KPI, filtros, tabla, detalle,
 * mapa geográfico y gráficas en una composición EDT-friendly.
 *
 * <p>Esta clase cumple el contrato del PLAN:</p>
 *
 * <pre>{@code
 *   ui.DashboardPanel(EventStore store, boolean demo)
 *     void refresh()
 *     void setAgents(List<Agent> agents)
 *     void setStatus(String status)
 * }</pre>
 *
 * <p>El panel sólo recibe el {@link EventStore} y el flag {@code demo}; no
 * realiza I/O. La hoja C inyecta los datos a través de
 * {@code EventStore#add(...)} y notifica el cambio. {@link #refresh()}
 * aplica los filtros actuales sobre el snapshot inmutable y propaga el
 * subset a todas las vistas.</p>
 *
 * <p>Toda interacción Swing se ejecuta en el EDT. Los setters externos se
 * reprograman automáticamente al EDT cuando se invocan desde otro hilo.</p>
 *
 * <p>El panel es reusable: cualquier subclase de {@code javax.swing.JPanel}
 * (incluido {@code JFrame}) puede alojarlo directamente porque este panel
 * extiende {@link JPanel}, o renderizarlo headless mediante
 * {@link #renderToImage()}.</p>
 */
public final class DashboardPanel extends JPanel {

    private final EventStore store;
    private final boolean demo;

    private final BannerPanel bannerPanel;
    private final KpiPanel kpiPanel;
    private final FiltersPanel filtersPanel;
    private final EventTablePanel eventTablePanel;
    private final DetailPanel detailPanel;
    private final GeoMapPanel geoMapPanel;
    private final ChartsPanel chartsPanel;

    private final List<Agent> agents = Collections.synchronizedList(new ArrayList<>());

    private FiltersPanel.FilterState currentFilter;

    private final List<StatusListener> statusListeners = new CopyOnWriteArrayList<>();

    private final Timer autoRefreshTimer;

    /**
     * Construye el panel. Debe invocarse en EDT.
     */
    public DashboardPanel(EventStore store, boolean demo) {
        super(new BorderLayout());
        if (store == null) {
            throw new IllegalArgumentException("store no puede ser null");
        }
        this.store = store;
        this.demo = demo;

        bannerPanel = new BannerPanel(demo);
        kpiPanel = new KpiPanel();
        filtersPanel = new FiltersPanel();
        eventTablePanel = new EventTablePanel();
        detailPanel = new DetailPanel();
        geoMapPanel = new GeoMapPanel();
        chartsPanel = new ChartsPanel();

        compose();
        wireListeners();
        // Estado inicial coherente con el periodo móvil por defecto
        // ("Última 1h") para que el primer refresh evalúe con la misma
        // ventana temporal que el usuario ve.
        currentFilter = filtersPanel.currentState();
        refresh();

        // El Timer interno NO se inicia: la hoja C coordina los refrescos
        // periódicos desde su propio ScheduledExecutorService.
        autoRefreshTimer = new Timer(2000, e -> refresh());
        autoRefreshTimer.setRepeats(false);
    }

    /**
     * Inicia el refresco automático. Útil cuando C conecta el dashboard a un
     * productor en vivo; en modo DEMO también es válido. Se debe llamar en
     * EDT.
     */
    public void startAutoRefresh(int intervalMs) {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(() -> startAutoRefresh(intervalMs));
            return;
        }
        autoRefreshTimer.setDelay(Math.max(250, intervalMs));
        if (!autoRefreshTimer.isRunning()) {
            autoRefreshTimer.start();
        }
    }

    public void stopAutoRefresh() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::stopAutoRefresh);
            return;
        }
        autoRefreshTimer.stop();
    }

    private void compose() {
        setBackground(Color.WHITE);

        // Header: banner + KPIs
        JPanel north = new JPanel(new BorderLayout());
        north.add(bannerPanel, BorderLayout.NORTH);
        north.add(kpiPanel, BorderLayout.CENTER);
        add(north, BorderLayout.NORTH);

        // Filtros
        add(filtersPanel, BorderLayout.SOUTH);

        // Centro: tabla + detalle a la izquierda, mapa + gráficas a la derecha
        JPanel center = new JPanel(new GridBagLayout());
        GridBagConstraints g = new GridBagConstraints();
        g.fill = GridBagConstraints.BOTH;
        g.weightx = 1.0;
        g.weighty = 0.55;

        g.gridx = 0;
        g.gridy = 0;
        center.add(eventTablePanel, g);

        g.gridx = 1;
        g.gridy = 0;
        g.weightx = 0.45;
        center.add(detailPanel, g);

        g.gridx = 0;
        g.gridy = 1;
        g.weighty = 0.45;
        g.weightx = 1.0;
        center.add(geoMapPanel, g);

        g.gridx = 1;
        g.gridy = 1;
        g.weightx = 0.45;
        center.add(chartsPanel, g);

        add(center, BorderLayout.CENTER);
    }

    private void wireListeners() {
        filtersPanel.addFilterListener(state -> {
            currentFilter = state;
            refresh();
        });

        eventTablePanel.addEntryListener(entry -> detailPanel.showEntry(entry));
    }

    /**
     * Sincroniza todas las vistas con el snapshot del {@link EventStore}
     * aplicando los filtros actuales. KPI, tabla, mapa y gráficas operan
     * sobre el mismo subset filtrado; los agentes del API no se filtran.
     *
     * <p>Sólo EDT. Las llamadas externas desde otros hilos se reprograman.
     * La hoja C puede llamar este método desde su propio
     * {@code ScheduledExecutorService} para refrescos periódicos.</p>
     */
    public void refresh() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::refresh);
            return;
        }
        // El periodo es móvil: lo recalculamos en cada refresh con el
        // instante actual, manteniendo el resto de filtros congelados. Esto
        // evita que la ventana temporal quede fija al momento del clic.
        currentFilter = filtersPanel.currentState();

        List<EventStore.Entry> snapshot = store.snapshot();

        // Una sola pasada sobre el snapshot: separa entries que pasan el filtro
        // y construye la lista de alertas filtradas. O(n) sin contains().
        List<EventStore.Entry> filteredEntries = new ArrayList<>();
        List<Alert> filteredAlerts = new ArrayList<>();
        for (EventStore.Entry e : snapshot) {
            if (e == null || e.alert() == null) {
                continue;
            }
            if (currentFilter.accepts(e.alert())) {
                filteredEntries.add(e);
                filteredAlerts.add(e.alert());
            }
        }

        // KPI eventos: subset filtrado. KPI agentes: lista API (independiente).
        List<Agent> snapshotAgents;
        synchronized (agents) {
            snapshotAgents = new ArrayList<>(agents);
        }
        kpiPanel.update(filteredAlerts, snapshotAgents);
        eventTablePanel.update(filteredEntries);

        // Mapa y gráficas comparten el subset filtrado.
        Instant from = currentFilter.from;
        Instant to = currentFilter.to;
        geoMapPanel.updateAlerts(filteredAlerts);
        chartsPanel.updateAlerts(filteredAlerts, from, to);

        // Banner: si no hay eventos visibles, marcar que la ingesta está pendiente.
        if (snapshot.isEmpty()) {
            kpiPanel.setIngestStatus("sin eventos");
        } else if (filteredAlerts.isEmpty()) {
            kpiPanel.setIngestStatus("filtrado vacío");
        } else {
            kpiPanel.setIngestStatus("ok (" + filteredAlerts.size() + ")");
        }
    }

    /**
     * Punto de enganche para que la hoja C coordine refrescos. El
     * {@link Timer} interno queda sin iniciar por defecto; C decide cuándo
     * llamar {@link #startAutoRefresh(int)}.
     */
    public Runnable refreshTask() {
        return this::refresh;
    }

    public void setAgents(List<Agent> agents) {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(() -> setAgents(agents));
            return;
        }
        synchronized (this.agents) {
            this.agents.clear();
            if (agents != null) {
                this.agents.addAll(agents);
            }
        }
        // En modo DEMO, si la API no devuelve agentes, completamos con los
        // agentId/agentName observados en los eventos. Así el filtro de agente
        // siempre puede acotar el subset, incluso sin manager real.
        List<Agent> merged = mergeAgentsFromEvents(agents);
        filtersPanel.setAgents(merged);
        refresh();
    }

    private List<Agent> mergeAgentsFromEvents(List<Agent> apiAgents) {
        Map<String, Agent> byId = new java.util.LinkedHashMap<>();
        if (apiAgents != null) {
            for (Agent a : apiAgents) {
                if (a == null || a.id() == null || a.id().isEmpty()) {
                    continue;
                }
                byId.put(a.id(), a);
            }
        }
        for (EventStore.Entry e : store.snapshot()) {
            if (e == null || e.alert() == null) {
                continue;
            }
            Alert a = e.alert();
            String id = a.agentId();
            if (id == null || id.isEmpty() || byId.containsKey(id)) {
                continue;
            }
            String name = a.agentName() == null || a.agentName().isEmpty() ? id : a.agentName();
            byId.put(id, new Agent(id, name, "synthetic", "", ""));
        }
        return new ArrayList<>(byId.values());
    }

    public void setStatus(String status) {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(() -> setStatus(status));
            return;
        }
        bannerPanel.setStatus(status);
        if (status == null) {
            return;
        }
        String lower = status.toLowerCase(Locale.ROOT);
        if (lower.contains("api")) {
            kpiPanel.setApiStatus(status);
        } else if (lower.contains("ldap")) {
            kpiPanel.setLdapStatus(status);
        } else if (lower.contains("ingest")) {
            kpiPanel.setIngestStatus(status);
        } else {
            // Si la cadena no menciona una categoría explícita, se aplica a las tres
            // luces como mensaje global.
            kpiPanel.setApiStatus(status);
            kpiPanel.setLdapStatus(status);
            kpiPanel.setIngestStatus(status);
        }
        for (StatusListener l : statusListeners) {
            l.onStatus(status);
        }
    }

    public void addStatusListener(StatusListener listener) {
        if (listener != null) {
            statusListeners.add(listener);
        }
    }

    /** Acceso a las sub-vistas para diagnóstico y tests. */
    public KpiPanel kpiPanel() { return kpiPanel; }
    public FiltersPanel filtersPanel() { return filtersPanel; }
    public EventTablePanel eventTablePanel() { return eventTablePanel; }
    public DetailPanel detailPanel() { return detailPanel; }
    public GeoMapPanel geoMapPanel() { return geoMapPanel; }
    public ChartsPanel chartsPanel() { return chartsPanel; }
    public BannerPanel bannerPanel() { return bannerPanel; }

    public boolean isDemo() {
        return demo;
    }

    public EventStore store() {
        return store;
    }

    /**
     * Renderiza el panel a una imagen. Pensado para uso headless (smoke).
     * Asegura que el panel tenga dimensiones válidas antes de pintar y delega
     * en {@link #paint(java.awt.Graphics)} para que se dibujen también los
     * hijos (mapa, tabla, gráficas, KPI). Sólo válido en EDT.
     */
    public BufferedImage renderToImage() {
        if (!SwingUtilities.isEventDispatchThread()) {
            throw new IllegalStateException(
                    "renderToImage debe invocarse desde el EDT");
        }
        Dimension size = getSize();
        if (size.width <= 0 || size.height <= 0) {
            size = new Dimension(1280, 720);
            setSize(size);
            setPreferredSize(size);
        }
        layoutTree(this);
        BufferedImage img = new BufferedImage(size.width, size.height,
                BufferedImage.TYPE_INT_RGB);
        Graphics2D g = img.createGraphics();
        try {
            paint(g);
        } finally {
            g.dispose();
        }
        return img;
    }
    private static void layoutTree(Container container) {
        container.doLayout();
        for (int i = 0; i < container.getComponentCount(); i++) {
            if (container.getComponent(i) instanceof Container child) {
                layoutTree(child);
            }
        }
    }


    /**
     * Helper para producir un JFrame real con el panel dentro. Útil para
     * pruebas visuales y para la demo del equipo.
     */
    public static JFrame showInFrame(DashboardPanel panel, String title) {
        JFrame frame = new JFrame(title == null ? "Dashboard Wazuh" : title);
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        frame.setContentPane(panel);
        frame.setSize(1280, 760);
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
        return frame;
    }

    /**
     * Listado resumido del estado, útil para el smoke headless.
     */
    public String describe() {
        return String.format(Locale.ROOT,
                "DashboardPanel{demo=%s, total=%s, high=%s, conUbic=%s, sinUbic=%s, "
                        + "agentes=%s, activos=%s, filtros=%s}",
                demo,
                kpiPanel.total(),
                kpiPanel.highSeverity(),
                kpiPanel.withLocation(),
                kpiPanel.withoutLocation(),
                kpiPanel.agents(),
                kpiPanel.activeAgents(),
                filtersPanel.describe());
    }

    @FunctionalInterface
    public interface StatusListener {
        void onStatus(String status);
    }
}