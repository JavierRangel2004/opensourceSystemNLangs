package edu.up.wazuh.ui;

import edu.up.wazuh.events.EventStore;
import edu.up.wazuh.model.Alert;
import edu.up.wazuh.model.DirectoryUser;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

/**
 * Panel de detalle del evento seleccionado y del usuario LDAP resuelto.
 *
 * <p>Reglas del PLAN aplicadas:</p>
 * <ul>
 *   <li>Mostrar {@link DirectoryUser} cuando la búsqueda LDAP tuvo éxito.</li>
 *   <li>Mostrar mensaje explícito cuando LDAP no está configurado o falló.</li>
 *   <li>No exponer el campo {@code full_log} ni payload original, por
 *       contrato del PLAN.</li>
 * </ul>
 */
public final class DetailPanel extends JPanel {

    private static final DateTimeFormatter UTC_FMT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss 'UTC'", Locale.ROOT);

    private final JTextArea detailArea;
    private final JTextArea ldapArea;

    public DetailPanel() {
        super(new BorderLayout());
        JPanel top = new JPanel(new BorderLayout());
        JLabel title = new JLabel("Detalle del evento");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 13f));
        title.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));
        top.add(title, BorderLayout.NORTH);

        detailArea = new JTextArea(8, 0);
        detailArea.setEditable(false);
        detailArea.setLineWrap(true);
        detailArea.setWrapStyleWord(true);
        detailArea.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));
        top.add(new JScrollPane(detailArea), BorderLayout.CENTER);
        add(top, BorderLayout.CENTER);

        JPanel bottom = new JPanel(new BorderLayout());
        JLabel ldapTitle = new JLabel("Detalle LDAP");
        ldapTitle.setFont(ldapTitle.getFont().deriveFont(Font.BOLD, 13f));
        ldapTitle.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));
        bottom.add(ldapTitle, BorderLayout.NORTH);

        ldapArea = new JTextArea(6, 0);
        ldapArea.setEditable(false);
        ldapArea.setLineWrap(true);
        ldapArea.setWrapStyleWord(true);
        ldapArea.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));
        bottom.add(new JScrollPane(ldapArea), BorderLayout.CENTER);
        add(bottom, BorderLayout.SOUTH);

        setPreferredSize(new Dimension(420, 320));
        clear();
    }

    public void clear() {
        detailArea.setText("Seleccione un evento de la tabla para ver el detalle.");
        ldapArea.setText("Sin consulta LDAP.");
        ldapArea.setForeground(Color.DARK_GRAY);
    }

    /** Texto combinado del bloque LDAP, para inspección en tests. */
    public String text() {
        return ldapArea.getText();
    }

    /** Texto combinado del bloque principal, para inspección en tests. */
    public String detailText() {
        return detailArea.getText();
    }

    public void showEntry(EventStore.Entry entry) {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(() -> showEntry(entry));
            return;
        }
        if (entry == null) {
            clear();
            return;
        }
        Alert a = entry.alert();
        StringBuilder sb = new StringBuilder();
        sb.append("Fecha UTC: ").append(formatUtc(a.timestamp())).append('\n');
        sb.append("Agente: ").append(safe(a.agentName())).append(" (").append(safe(a.agentId())).append(")\n");
        sb.append("Regla: ").append(safe(a.ruleId())).append('\n');
        sb.append("Nivel: ").append(a.level()).append('\n');
        sb.append("Descripcion: ").append(safe(a.description())).append('\n');
        sb.append("Pais: ").append(safe(a.country())).append('\n');
        sb.append("Coordenadas: ");
        if (a.latitude() != null && a.longitude() != null) {
            sb.append(String.format(Locale.ROOT, "lat %.4f, lon %.4f",
                    a.latitude(), a.longitude()));
        } else {
            sb.append("(sin ubicacion)");
        }
        sb.append('\n');
        sb.append("Integracion: ").append(safe(a.integration())).append('\n');
        detailArea.setText(sb.toString());

        DirectoryUser u = entry.user();
        String status = entry.ldapStatus() == null ? "" : entry.ldapStatus();
        String lower = status.toLowerCase(Locale.ROOT);
        if (lower.isEmpty() || "found".equals(lower) || "ok".equals(lower)
                || "encontrado".equals(lower)) {
            if (u != null) {
                ldapArea.setForeground(new Color(20, 90, 20));
                ldapArea.setText(String.format(Locale.ROOT,
                        "Usuario: %s%nNombre: %s%nEmail: %s%nDepartamento: %s%nEstado: %s",
                        safe(u.username()), safe(u.displayName()), safe(u.email()),
                        safe(u.department()),
                        status.isEmpty() ? "found" : status));
            } else {
                ldapArea.setForeground(Color.DARK_GRAY);
                ldapArea.setText("Evento sin usuario: no se realizo busqueda LDAP.");
            }
        } else if ("missing".equals(lower)) {
            ldapArea.setForeground(new Color(170, 130, 30));
            ldapArea.setText("LDAP devolvio un resultado vacio para el usuario.");
        } else if ("not-applicable".equals(lower)) {
            ldapArea.setForeground(Color.DARK_GRAY);
            ldapArea.setText("El evento no incluye nombre de usuario; no se ejecuto busqueda.");
        } else if ("not-configured".equals(lower)) {
            ldapArea.setForeground(new Color(170, 130, 30));
            ldapArea.setText("LDAP no configurado. Inyecte las variables LDAP_URL, "
                    + "LDAP_BIND_DN, LDAP_BIND_PASSWORD y LDAP_BASE_DN para habilitar "
                    + "la busqueda.");
        } else if ("error".equals(lower)) {
            ldapArea.setForeground(new Color(170, 30, 30));
            ldapArea.setText("Error LDAP durante la busqueda (no se expone el detalle).");
        } else {
            // Estados desconocidos: se muestran literal para diagnóstico.
            ldapArea.setForeground(new Color(170, 30, 30));
            ldapArea.setText("Estado LDAP desconocido: " + status
                    + (u == null ? "" : "%nUsuario: " + safe(u.username())));
        }
    }

    private static String formatUtc(Instant ts) {
        if (ts == null) {
            return "-";
        }
        return UTC_FMT.format(LocalDateTime.ofInstant(ts, ZoneOffset.UTC));
    }

    private static String safe(String s) {
        return s == null || s.isEmpty() ? "-" : s;
    }
}