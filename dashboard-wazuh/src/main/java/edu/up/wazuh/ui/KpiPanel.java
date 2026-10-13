package edu.up.wazuh.ui;

import edu.up.wazuh.model.Agent;
import edu.up.wazuh.model.Alert;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingConstants;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridLayout;
import java.util.List;

/**
 * Panel de KPI. Muestra conteos visibles y el estado de API, LDAP e ingesta.
 *
 * <p>Los conteos de eventos se calculan sobre el subset filtrado que entrega
 * {@link DashboardPanel}; la lista de agentes proviene del API y se trata
 * aparte, sin pasar por el filtro de eventos.</p>
 *
 * <p>Regla del PLAN: <em>"KPI conteos visibles, estado API/LDAP/ingesta"</em>.
 * Esta clase entrega los seis indicadores canónicos y tres luces de estado.</p>
 */
public final class KpiPanel extends JPanel {

    private final JLabel totalLabel = new JLabel("0");
    private final JLabel highLabel = new JLabel("0");
    private final JLabel withLocationLabel = new JLabel("0");
    private final JLabel withoutLocationLabel = new JLabel("0");
    private final JLabel agentsLabel = new JLabel("0");
    private final JLabel activeAgentsLabel = new JLabel("0");
    private final JLabel apiStatus = new JLabel("--");
    private final JLabel ldapStatus = new JLabel("--");
    private final JLabel ingestStatus = new JLabel("--");

    public KpiPanel() {
        super(new BorderLayout());
        JPanel grid = new JPanel(new GridLayout(2, 4, 8, 8));
        grid.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        grid.add(card("Eventos total", totalLabel, new Color(220, 235, 250)));
        grid.add(card("Severidad >= 10", highLabel, new Color(250, 220, 220)));
        grid.add(card("Con ubicacion", withLocationLabel, new Color(220, 245, 220)));
        grid.add(card("Sin ubicacion", withoutLocationLabel, new Color(245, 235, 220)));
        grid.add(card("Agentes", agentsLabel, new Color(230, 230, 250)));
        grid.add(card("Agentes activos", activeAgentsLabel, new Color(220, 250, 235)));
        JPanel statusBlock = new JPanel(new GridLayout(1, 3, 4, 4));
        statusBlock.add(statusCard("API Wazuh", apiStatus));
        statusBlock.add(statusCard("LDAP", ldapStatus));
        statusBlock.add(statusCard("Ingesta", ingestStatus));
        grid.add(statusBlock);
        add(grid, BorderLayout.CENTER);
    }

    private JPanel card(String title, JLabel value, Color bg) {
        JPanel p = new JPanel(new BorderLayout());
        p.setBackground(bg);
        p.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(180, 180, 180)),
                BorderFactory.createEmptyBorder(6, 8, 6, 8)));
        JLabel t = new JLabel(title, SwingConstants.LEFT);
        t.setFont(t.getFont().deriveFont(Font.PLAIN, 11f));
        value.setFont(value.getFont().deriveFont(Font.BOLD, 18f));
        p.add(t, BorderLayout.NORTH);
        p.add(value, BorderLayout.CENTER);
        p.setPreferredSize(new Dimension(150, 64));
        return p;
    }

    private JPanel statusCard(String title, JLabel value) {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(180, 180, 180)),
                BorderFactory.createEmptyBorder(6, 8, 6, 8)));
        JLabel t = new JLabel(title, SwingConstants.LEFT);
        t.setFont(t.getFont().deriveFont(Font.PLAIN, 11f));
        value.setFont(value.getFont().deriveFont(Font.BOLD, 12f));
        p.add(t, BorderLayout.NORTH);
        p.add(value, BorderLayout.CENTER);
        p.setPreferredSize(new Dimension(150, 64));
        return p;
    }

    /**
     * Recalcula los conteos a partir de la lista de eventos y agentes.
     * Se ejecuta en EDT por el llamador.
     */
    public void update(List<Alert> alerts, List<Agent> agents) {
        int total = alerts == null ? 0 : alerts.size();
        int high = 0;
        int withLoc = 0;
        int withoutLoc = 0;
        if (alerts != null) {
            for (Alert a : alerts) {
                if (a == null) {
                    continue;
                }
                if (a.level() >= 10) {
                    high++;
                }
                Double lat = a.latitude();
                Double lon = a.longitude();
                if (lat == null || lon == null
                        || Double.isNaN(lat) || Double.isNaN(lon)
                        || Double.isInfinite(lat) || Double.isInfinite(lon)
                        || lat < -90.0 || lat > 90.0
                        || lon < -180.0 || lon > 180.0) {
                    withoutLoc++;
                } else {
                    withLoc++;
                }
            }
        }
        int totalAgents = agents == null ? 0 : agents.size();
        int activeAgents = 0;
        if (agents != null) {
            for (Agent a : agents) {
                if (a == null) {
                    continue;
                }
                String status = a.status() == null ? "" : a.status().toLowerCase();
                if (status.contains("active")) {
                    activeAgents++;
                }
            }
        }
        totalLabel.setText(Integer.toString(total));
        highLabel.setText(Integer.toString(high));
        withLocationLabel.setText(Integer.toString(withLoc));
        withoutLocationLabel.setText(Integer.toString(withoutLoc));
        agentsLabel.setText(Integer.toString(totalAgents));
        activeAgentsLabel.setText(Integer.toString(activeAgents));
    }

    /** Actualiza las tres luces de estado (API, LDAP, ingesta). */
    public void setApiStatus(String text) {
        apiStatus.setText(text == null ? "--" : text);
        apiStatus.setForeground(deriveColor(text));
    }

    public void setLdapStatus(String text) {
        ldapStatus.setText(text == null ? "--" : text);
        ldapStatus.setForeground(deriveColor(text));
    }

    public void setIngestStatus(String text) {
        ingestStatus.setText(text == null ? "--" : text);
        ingestStatus.setForeground(deriveColor(text));
    }

    private static Color deriveColor(String text) {
        if (text == null) {
            return Color.DARK_GRAY;
        }
        String t = text.toLowerCase();
        if (t.contains("ok") || t.contains("connected") || t.contains("exitosa") || t.contains("ready")) {
            return new Color(20, 110, 20);
        }
        if (t.contains("error") || t.contains("fail") || t.contains("caido") || t.contains("off")) {
            return new Color(170, 30, 30);
        }
        if (t.contains("config") || t.contains("pendiente") || t.contains("no config")) {
            return new Color(170, 130, 30);
        }
        return Color.DARK_GRAY;
    }

    /** Acceso de sólo lectura para tests. */
    public String total() { return totalLabel.getText(); }
    public String highSeverity() { return highLabel.getText(); }
    public String withLocation() { return withLocationLabel.getText(); }
    public String withoutLocation() { return withoutLocationLabel.getText(); }
    public String agents() { return agentsLabel.getText(); }
    public String activeAgents() { return activeAgentsLabel.getText(); }
    public String apiStatusText() { return apiStatus.getText(); }
    public String ldapStatusText() { return ldapStatus.getText(); }
    public String ingestStatusText() { return ingestStatus.getText(); }
}