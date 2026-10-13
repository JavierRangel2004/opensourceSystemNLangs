package edu.up.wazuh.ui;

import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingConstants;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Font;

/**
 * Banner superior que distingue claramente modo DEMO y modo REAL.
 *
 * <p>El PLAN exige: <em>"banner DEMO vs REAL"</em>. Esta franja es el primer
 * elemento visible del dashboard; un color verde y la palabra "DEMO"
 * indican que los datos son sintéticos (etiquetados MUESTRA/DEMO por la
 * hoja C). Un color rojo y "REAL" sólo aparecen cuando C inyecta datos del
 * manager real de Wazuh.</p>
 *
 * <p>El panel también muestra el subtítulo "Dashboard Wazuh — Universidad
 * de Panamá" para reforzar la orientación institucional.</p>
 */
public final class BannerPanel extends JPanel {

    private final JLabel modeLabel;
    private final boolean demo;

    public BannerPanel(boolean demo) {
        super(new BorderLayout());
        this.demo = demo;
        setBackground(demo ? new Color(220, 245, 220) : new Color(245, 220, 220));
        setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0,
                demo ? new Color(140, 200, 140) : new Color(200, 120, 120)));

        JLabel title = new JLabel("Dashboard Wazuh - Universidad Panamericana",
                SwingConstants.LEFT);
        title.setFont(title.getFont().deriveFont(Font.BOLD, 14f));
        title.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));
        add(title, BorderLayout.WEST);

        modeLabel = new JLabel(demo ? "DEMO (datos sinteticos)" : "REAL (Wazuh manager)");
        modeLabel.setFont(modeLabel.getFont().deriveFont(Font.BOLD, 13f));
        modeLabel.setForeground(demo ? new Color(40, 110, 40) : new Color(160, 40, 40));
        modeLabel.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 8));
        add(modeLabel, BorderLayout.EAST);
    }

    public boolean isDemo() {
        return demo;
    }

    public void setStatus(String status) {
        if (status != null) {
            modeLabel.setToolTipText(status);
        }
    }
}