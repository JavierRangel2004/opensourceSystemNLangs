package edu.up.wazuh.ui;

import edu.up.wazuh.events.EventStore;
import edu.up.wazuh.model.Alert;

import javax.swing.BorderFactory;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumn;
import java.awt.Color;
import java.awt.Component;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Tabla de eventos. La selección notifica a los listeners que muestran el
 * detalle del usuario LDAP y, opcionalmente, resaltan el símbolo en el mapa.
 *
 * <p>El modelo se reemplaza por completo en {@link #update(List)} para evitar
 * arrastrar estado entre refrescos. La lista interna es inmutable y se
 * comparte con el resto del dashboard para que el mapa y las gráficas operen
 * sobre el mismo subset filtrado.</p>
 */
public final class EventTablePanel extends JPanel {

    private static final DateTimeFormatter UTC_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss 'UTC'", Locale.ROOT);

    private final JTable table;
    private final EventTableModel model;
    private final List<EntryListener> listeners = new CopyOnWriteArrayList<>();
    private List<EventStore.Entry> entries = Collections.emptyList();
    private boolean restoringSelection;

    public EventTablePanel() {
        super(new java.awt.BorderLayout());
        model = new EventTableModel();
        table = new JTable(model);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoCreateRowSorter(true);
        table.setFillsViewportHeight(true);
        table.setRowHeight(22);
        table.getTableHeader().setReorderingAllowed(false);

        // Renderers para que las celdas de severidad se vean con color de fondo.
        DefaultTableCellRenderer renderer = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable t, Object value, boolean isSelected,
                                                           boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(t, value, isSelected, hasFocus, row, column);
                int modelRow = t.convertRowIndexToModel(row);
                if (!isSelected && modelRow >= 0 && modelRow < entries.size()) {
                    int level = entries.get(modelRow).alert().level();
                    c.setBackground(colorForLevel(level));
                    c.setForeground(Color.BLACK);
                }
                return c;
            }
        };
        for (int i = 0; i < table.getColumnCount(); i++) {
            table.getColumnModel().getColumn(i).setCellRenderer(renderer);
        }

        // Selección -> notificar listeners.
        table.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                if (restoringSelection || e.getValueIsAdjusting()) {
                    return;
                }
                int viewRow = table.getSelectedRow();
                if (viewRow < 0) {
                    fireSelected(null);
                    return;
                }
                int modelRow = table.convertRowIndexToModel(viewRow);
                if (modelRow >= 0 && modelRow < entries.size()) {
                    fireSelected(entries.get(modelRow));
                }
            }
        });
        JScrollPane scroll = new JScrollPane(table);
        scroll.setColumnHeaderView(table.getTableHeader());
        scroll.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
        add(scroll, java.awt.BorderLayout.CENTER);

        // Anchos razonables por defecto.
        configureColumns();
    }

    private void configureColumns() {
        int[] widths = {120, 100, 70, 60, 240, 110, 80, 90};
        for (int i = 0; i < widths.length && i < table.getColumnCount(); i++) {
            TableColumn c = table.getColumnModel().getColumn(i);
            c.setPreferredWidth(widths[i]);
        }
    }

    public void addEntryListener(EntryListener l) {
        if (l != null) {
            listeners.add(l);
        }
    }

    private void fireSelected(EventStore.Entry e) {
        for (EntryListener l : listeners) {
            l.onEntrySelected(e);
        }
    }

    public void update(List<EventStore.Entry> next) {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(() -> update(next));
            return;
        }
        EventStore.Entry previousEntry = selectedEntry();
        String previousId = previousEntry == null || previousEntry.alert() == null
                ? null : previousEntry.alert().id();
        this.entries = next == null ? Collections.emptyList() : List.copyOf(next);
        int restored = -1;
        if (previousId != null) {
            for (int i = 0; i < this.entries.size(); i++) {
                EventStore.Entry entry = this.entries.get(i);
                if (entry != null && entry.alert() != null
                        && previousId.equals(entry.alert().id())) {
                    restored = i;
                    break;
                }
            }
        }
        boolean selectionChanged = previousId != null && restored < 0;
        EventStore.Entry selectedAfter = restored < 0 ? null : this.entries.get(restored);
        boolean selectedUpdated = previousEntry != null && selectedAfter != null
                && !previousEntry.equals(selectedAfter);
        restoringSelection = true;
        try {
            model.setEntries(this.entries);
            if (restored < 0) {
                table.clearSelection();
            } else {
                int viewRow = table.convertRowIndexToView(restored);
                if (viewRow >= 0) {
                    table.setRowSelectionInterval(viewRow, viewRow);
                } else {
                    table.clearSelection();
                    selectionChanged = previousId != null;
                    selectedAfter = null;
                }
            }
        } finally {
            restoringSelection = false;
        }
        if (selectionChanged || selectedUpdated) {
            fireSelected(selectedAfter);
        }
    }

    public EventStore.Entry selectedEntry() {
        int row = table.getSelectedRow();
        if (row < 0) {
            return null;
        }
        int modelRow = table.convertRowIndexToModel(row);
        if (modelRow < 0 || modelRow >= entries.size()) {
            return null;
        }
        return entries.get(modelRow);
    }

    /**
     * Selecciona la fila del modelo en el índice dado. Sólo para tests; la
     * selección visible del usuario pasa por la propia tabla.
     */
    public void setSelectedIndexForTest(int modelIndex) {
        if (modelIndex < 0 || modelIndex >= entries.size()) {
            table.clearSelection();
            return;
        }
        int viewRow = table.convertRowIndexToView(modelIndex);
        if (viewRow >= 0) {
            table.setRowSelectionInterval(viewRow, viewRow);
        }
    }

    public int entryCount() {
        return entries.size();
    }

    public List<EventStore.Entry> entries() {
        return entries;
    }

    private static Color colorForLevel(int level) {
        if (level >= 13) {
            return new Color(255, 200, 200);
        }
        if (level >= 10) {
            return new Color(255, 220, 200);
        }
        if (level >= 6) {
            return new Color(255, 245, 200);
        }
        if (level >= 3) {
            return new Color(230, 245, 200);
        }
        return Color.WHITE;
    }

    @FunctionalInterface
    public interface EntryListener {
        void onEntrySelected(EventStore.Entry entry);
    }

    private static final class EventTableModel extends AbstractTableModel {
        private static final String[] COLUMNS = {
                "Fecha (UTC)", "Agente", "ID regla", "Nivel", "Descripcion",
                "Usuario", "Pais", "Estado LDAP"
        };

        private List<EventStore.Entry> rows = Collections.emptyList();

        void setEntries(List<EventStore.Entry> rows) {
            this.rows = rows;
            fireTableDataChanged();
        }

        @Override
        public int getRowCount() {
            return rows.size();
        }

        @Override
        public int getColumnCount() {
            return COLUMNS.length;
        }

        @Override
        public String getColumnName(int column) {
            return COLUMNS[column];
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (rowIndex < 0 || rowIndex >= rows.size()) {
                return "";
            }
            EventStore.Entry e = rows.get(rowIndex);
            Alert a = e.alert();
            switch (columnIndex) {
                case 0:
                    return formatUtc(a.timestamp());
                case 1:
                    return a.agentName() + " (" + a.agentId() + ")";
                case 2:
                    return a.ruleId();
                case 3:
                    return a.level();
                case 4:
                    return a.description();
                case 5:
                    return a.username() == null || a.username().isEmpty() ? "-" : a.username();
                case 6:
                    return a.country() == null || a.country().isEmpty() ? "-" : a.country();
                case 7:
                    return e.ldapStatus() == null ? "-" : e.ldapStatus();
                default:
                    return "";
            }
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            if (columnIndex == 3) {
                return Integer.class;
            }
            return String.class;
        }

        private static String formatUtc(Instant ts) {
            if (ts == null) {
                return "-";
            }
            LocalDateTime utc = LocalDateTime.ofInstant(ts, ZoneOffset.UTC);
            return UTC_FMT.format(utc);
        }
    }
}