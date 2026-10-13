package edu.up.wazuh.ui;

import edu.up.wazuh.model.Agent;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.DefaultComboBoxModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSpinner;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Color;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Filtros mínimos del dashboard: nivel mínimo de severidad, agente (todos o
 * uno concreto), texto libre sobre la descripción y periodo (en horas).
 *
 * <p>El panel publica un conjunto inmutable de {@link FilterState} cada vez
 * que el usuario cambia un control. Los listeners se notifican en EDT.</p>
 *
 * <p>El periodo es móvil y se recalcula al consultar {@link #currentState()}.
 * El resto de filtros permanece congelado hasta que el usuario los cambie.</p>
 *
 * <p>{@link #setAgents(List)} preserva el agente seleccionado si su id sigue
 * presente, no emite eventos durante la actualización y no parsea la
 * etiqueta visible para identificar al agente (usa el id del
 * {@code Agent}).</p>
 */
public final class FiltersPanel extends JPanel {

    /** Estado inmutable que viaja desde el panel hasta el resto del dashboard. */
    public static final class FilterState {
        public final int minLevel;
        public final String agentId; // null = todos
        public final String text;    // null o cadena vacía = sin filtro
        public final Instant from;
        public final Instant to;

        public FilterState(int minLevel, String agentId, String text, Instant from, Instant to) {
            this.minLevel = minLevel;
            this.agentId = (agentId == null || agentId.isEmpty()) ? null : agentId;
            this.text = (text == null) ? "" : text.trim();
            this.from = from;
            this.to = to;
        }

        public boolean accepts(edu.up.wazuh.model.Alert a) {
            if (a == null) {
                return false;
            }
            if (a.level() < minLevel) {
                return false;
            }
            if (agentId != null && !agentId.equals(a.agentId())) {
                return false;
            }
            if (!text.isEmpty()) {
                String hay = (a.description() == null ? "" : a.description())
                        + " " + (a.ruleId() == null ? "" : a.ruleId())
                        + " " + (a.username() == null ? "" : a.username())
                        + " " + (a.country() == null ? "" : a.country())
                        + " " + (a.agentName() == null ? "" : a.agentName());
                if (!hay.toLowerCase(Locale.ROOT).contains(text.toLowerCase(Locale.ROOT))) {
                    return false;
                }
            }
            Instant t = a.timestamp();
            if (t != null) {
                if (from != null && t.isBefore(from)) {
                    return false;
                }
                if (to != null && t.isAfter(to)) {
                    return false;
                }
            }
            return true;
        }
    }

    /** Etiqueta del agente (lo que ve el usuario) indexada por id. */
    static final class AgentOption {
        final String id;
        final String label;
        AgentOption(String id, String label) {
            this.id = id;
            this.label = label;
        }
        @Override public String toString() { return label; }
    }

    private static final String ALL_AGENTS = "(todos)";
    private static final AgentOption ALL_OPTION = new AgentOption(ALL_AGENTS, ALL_AGENTS);

    private final JSpinner levelSpinner;
    private final JComboBox<AgentOption> agentCombo;
    private final JTextField textField;
    private final JComboBox<String> periodCombo;
    private final JButton resetButton;

    private final List<FilterListener> listeners = new CopyOnWriteArrayList<>();

    private int currentLevel;
    private AgentOption currentAgent;
    private String currentText;
    private int periodIndex;

    private boolean suppressEvents;

    public FiltersPanel() {
        super(new BorderLayout());
        JPanel row = new JPanel();
        row.setLayout(new BoxLayout(row, BoxLayout.X_AXIS));
        row.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));

        row.add(new JLabel("Nivel mínimo:"));
        levelSpinner = new JSpinner(new SpinnerNumberModel(0, 0, 15, 1));
        levelSpinner.setMaximumSize(new java.awt.Dimension(70, 26));
        row.add(levelSpinner);
        row.add(Box.createHorizontalStrut(8));

        row.add(new JLabel("Agente:"));
        agentCombo = new JComboBox<>(new AgentOption[]{ALL_OPTION});
        agentCombo.setMaximumSize(new java.awt.Dimension(220, 26));
        row.add(agentCombo);
        row.add(Box.createHorizontalStrut(8));

        row.add(new JLabel("Búsqueda:"));
        textField = new JTextField(20);
        textField.setMaximumSize(new java.awt.Dimension(280, 26));
        row.add(textField);
        row.add(Box.createHorizontalStrut(8));

        row.add(new JLabel("Periodo:"));
        periodCombo = new JComboBox<>(new String[]{
                "Última 1h", "Últimas 6h", "Últimas 24h", "Últimos 7 días", "Todo"});
        periodCombo.setMaximumSize(new java.awt.Dimension(160, 26));
        row.add(periodCombo);
        row.add(Box.createHorizontalStrut(8));

        resetButton = new JButton("Restablecer");
        resetButton.setBackground(new Color(245, 245, 245));
        row.add(resetButton);

        add(row, BorderLayout.CENTER);

        levelSpinner.addChangeListener(e -> onChange());
        agentCombo.addActionListener(e -> onChange());
        textField.addActionListener(e -> onChange());
        periodCombo.addActionListener(e -> onChange());
        resetButton.addActionListener(e -> reset());

        // Estado inicial coherente: nivel=0, todos, sin texto, periodo=1h.
        currentLevel = 0;
        currentAgent = ALL_OPTION;
        currentText = "";
        periodIndex = 0;
    }

    public void addFilterListener(FilterListener listener) {
        if (listener != null) {
            listeners.add(listener);
        }
    }

    /**
     * Reemplaza la lista de agentes del combo preservando el id actualmente
     * seleccionado si todavía existe. Emite un único evento de cambio
     * (o ninguno si no se cambió nada).
     */
    public void setAgents(List<Agent> agents) {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(() -> setAgents(agents));
            return;
        }
        AgentOption previous = currentAgent == null ? ALL_OPTION : currentAgent;
        String previousId = previous.id;
        List<Agent> copy = new ArrayList<>();
        if (agents != null) {
            for (Agent agent : agents) {
                if (agent != null && agent.id() != null && !agent.id().isBlank()) {
                    copy.add(agent);
                }
            }
        }
        copy.sort((a, b) -> {
            String an = a.name() == null ? "" : a.name();
            String bn = b.name() == null ? "" : b.name();
            return an.compareTo(bn);
        });
        AgentOption[] options = new AgentOption[copy.size() + 1];
        options[0] = ALL_OPTION;
        for (int i = 0; i < copy.size(); i++) {
            Agent a = copy.get(i);
            String label = (a.name() == null || a.name().isEmpty()
                    ? a.id() : a.name()) + " (" + a.id() + ")";
            options[i + 1] = new AgentOption(a.id(), label);
        }
        AgentOption restored = ALL_OPTION;
        for (int i = 0; i < options.length; i++) {
            if (options[i].id.equals(previousId)) {
                restored = options[i];
                break;
            }
        }
        boolean changed = !previousId.equals(restored.id);
        boolean sameOptions = agentCombo.getItemCount() == options.length;
        if (sameOptions) {
            for (int i = 0; i < options.length; i++) {
                Object existing = agentCombo.getItemAt(i);
                if (!(existing instanceof AgentOption)
                        || !options[i].id.equals(((AgentOption) existing).id)
                        || !options[i].label.equals(((AgentOption) existing).label)) {
                    sameOptions = false;
                    break;
                }
            }
        }
        currentAgent = restored;
        if (!sameOptions) {
            suppressEvents = true;
            try {
                agentCombo.setModel(new DefaultComboBoxModel<>(options));
                agentCombo.setSelectedItem(restored);
            } finally {
                suppressEvents = false;
            }
        }
        if (changed) {
            emit();
        }
    }

    /**
     * Estado actual con el periodo recalculado a "ahora". Pensado para que el
     * {@link DashboardPanel} lo invoque en cada refresh; no emite eventos.
     */
    public FilterState currentState() {
        Instant[] window = computePeriodWindow(Instant.now(), periodIndex);
        // "(todos)" es un valor centinela: si está presente, NO se aplica
        // filtro de agente (agentId debe ser null en FilterState).
        String agentId = null;
        if (currentAgent != null && !ALL_AGENTS.equals(currentAgent.id)) {
            agentId = currentAgent.id;
        }
        return new FilterState(currentLevel, agentId, currentText, window[0], window[1]);
    }


    private void onChange() {
        if (suppressEvents) {
            return;
        }
        currentLevel = (Integer) levelSpinner.getValue();
        Object sel = agentCombo.getSelectedItem();
        currentAgent = (sel instanceof AgentOption) ? (AgentOption) sel : ALL_OPTION;
        currentText = textField.getText();
        periodIndex = periodCombo.getSelectedIndex();
        emit();
    }

    private void reset() {
        suppressEvents = true;
        try {
            levelSpinner.setValue(0);
            agentCombo.setSelectedItem(ALL_OPTION);
            textField.setText("");
            periodCombo.setSelectedIndex(0);
        } finally {
            suppressEvents = false;
        }
        currentLevel = 0;
        currentAgent = ALL_OPTION;
        currentText = "";
        periodIndex = 0;
        emit();
    }

    private void emit() {
        FilterState s = currentState();
        for (FilterListener l : listeners) {
            l.onFilterChanged(s);
        }
    }

    /**
     * Calcula la ventana temporal móvil según el índice del combo. Devuelve
     * un par {@code [from, to]}. Cuando {@code periodIndex < 0} o
     * {@code >=4} se considera "todo" y devuelve {@code [null, null]}.
     */
    public static Instant[] computePeriodWindow(Instant now, int periodIndex) {
        if (now == null || periodIndex < 0 || periodIndex >= 4) {
            return new Instant[]{null, null};
        }
        Instant to = now;
        Instant from;
        switch (periodIndex) {
            case 0: from = now.minusSeconds(3600L); break;
            case 1: from = now.minusSeconds(6 * 3600L); break;
            case 2: from = now.minusSeconds(24 * 3600L); break;
            case 3: from = now.minusSeconds(7 * 24 * 3600L); break;
            default: from = null;
        }
        return new Instant[]{from, to};
    }

    /** Resumen legible del estado actual, para diagnóstico/tests. */
    public String describe() {
        FilterState s = currentState();
        DateTimeFormatter fmt = DateTimeFormatter.ISO_INSTANT;
        return String.format(Locale.ROOT,
                "minLevel=%d agent=%s text='%s' from=%s to=%s",
                s.minLevel,
                s.agentId == null ? "(todos)" : s.agentId,
                s.text,
                s.from == null ? "(sin límite)" : fmt.format(s.from),
                s.to == null ? "(sin límite)" : fmt.format(s.to));
    }

    @FunctionalInterface
    public interface FilterListener {
        void onFilterChanged(FilterState state);
    }
}