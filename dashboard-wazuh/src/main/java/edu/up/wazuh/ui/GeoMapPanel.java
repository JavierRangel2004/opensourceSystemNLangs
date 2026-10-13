package edu.up.wazuh.ui;

import edu.up.wazuh.model.Alert;

import javax.swing.JPanel;
import java.awt.AlphaComposite;
import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseMotionAdapter;
import java.awt.geom.Ellipse2D;
import java.awt.geom.Path2D;
import java.awt.geom.Point2D;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import javax.imageio.ImageIO;

/**
 * Panel geográfico que muestra los eventos con coordenadas sobre un mapa base
 * Natural Earth (dominio público).
 *
 * <p>Reglas del PLAN aplicadas:</p>
 * <ul>
 *   <li>Sólo EDT para mutaciones: el temporizador de tooltip repinta y los
 *       setters externos disparan {@code repaint()} que Swing ejecuta en EDT.</li>
 *   <li>Sin red ni I/O bloqueante: el GeoJSON se carga desde el classpath al
 *       construir el panel y se conserva en memoria.</li>
 *   <li>Símbolos proporcionales al conteo de eventos por ubicación y coloreados
 *       por la mayor severidad observada.</li>
 *   <li>Eventos sin coordenadas válidas se cuentan aparte y se reportan en la
 *       esquina superior; nunca se proyectan a (0,0).</li>
 * </ul>
 *
 * <p>Si el recurso de Natural Earth no se encuentra, el panel dibuja sólo la
 * cuadrícula y los símbolos, sin continentes. Esto se documenta explícitamente
 * al usuario en el mensaje "mapa base no disponible".</p>
 */
public final class GeoMapPanel extends JPanel {

    private static final Color OCEAN = new Color(232, 244, 252);
    private static final Color LAND = new Color(238, 238, 224);
    private static final Color GRID = new Color(180, 200, 220);
    private static final Color COUNTRY_OUTLINE = new Color(140, 140, 130);
    private static final Color TEXT = new Color(40, 40, 40);
    private static final Color LEGEND_BACKGROUND = new Color(255, 255, 255, 220);
    private static final Color[] SEVERITY_COLORS = {
            new Color(80, 170, 90), new Color(220, 200, 70),
            new Color(230, 130, 50), new Color(220, 60, 60),
            new Color(120, 30, 30)};
    private static final String[] SEVERITY_LABELS = {"0 - 2", "3 - 5", "6 - 9", "10 - 12", "13 - 15"};

    private final NaturalEarthMap baseMap;
    private final List<MapSymbol> symbols = new ArrayList<>();
    private int noLocationCount;
    private MapSymbol hoveredSymbol;

    public GeoMapPanel() {
        this(NaturalEarthMap.loadDefault());
    }

    public GeoMapPanel(NaturalEarthMap baseMap) {
        this.baseMap = baseMap == null ? NaturalEarthMap.loadDefault() : baseMap;
        setBackground(OCEAN);
        setPreferredSize(new Dimension(800, 420));
        addMouseListener(new MouseAdapter() {
            @Override
            public void mouseExited(MouseEvent e) {
                if (hoveredSymbol != null) {
                    hoveredSymbol = null;
                    repaint();
                }
            }
        });
        addMouseMotionListener(new MouseMotionAdapter() {
            @Override
            public void mouseMoved(MouseEvent e) {
                MapSymbol hit = findSymbolAt(e.getX(), e.getY());
                if (hit != hoveredSymbol) {
                    hoveredSymbol = hit;
                    repaint();
                }
            }
        });
    }

    /**
     * Reemplaza el conjunto de símbolos a partir de una lista de alertas. Las
     * alertas sin coordenadas válidas se cuentan aparte; las que tienen
     * coordenadas se agrupan por ubicación para producir símbolos
     * proporcionales.
     */
    public void updateAlerts(List<Alert> alerts) {
        Map<LocationKey, List<Alert>> grouped = new HashMap<>();
        noLocationCount = 0;
        if (alerts != null) {
            for (Alert a : alerts) {
                if (a == null) {
                    continue;
                }
                Double lat = a.latitude();
                Double lon = a.longitude();
                if (lat == null || lon == null
                        || Double.isNaN(lat) || Double.isNaN(lon)
                        || Double.isInfinite(lat) || Double.isInfinite(lon)
                        || lat < -90.0 || lat > 90.0
                        || lon < -180.0 || lon > 180.0) {
                    noLocationCount++;
                    continue;
                }
                LocationKey key = new LocationKey(round(lat, 2), round(lon, 2));
                grouped.computeIfAbsent(key, k -> new ArrayList<>()).add(a);
            }
        }
        symbols.clear();
        for (Map.Entry<LocationKey, List<Alert>> entry : grouped.entrySet()) {
            symbols.add(new MapSymbol(entry.getKey(), entry.getValue()));
        }
        hoveredSymbol = null;
        repaint();
    }

    private static double round(double v, int decimals) {
        double scale = Math.pow(10, decimals);
        return Math.round(v * scale) / scale;
    }

    private MapSymbol findSymbolAt(int x, int y) {
        for (int i = symbols.size() - 1; i >= 0; i--) {
            MapSymbol s = symbols.get(i);
            double dx = x - s.pixelX;
            double dy = y - s.pixelY;
            if (dx * dx + dy * dy <= s.radius * s.radius) {
                return s;
            }
        }
        return null;
    }

    @Override
    protected void paintComponent(Graphics g) {
        super.paintComponent(g);
        Graphics2D g2 = (Graphics2D) g.create();
        try {
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                    RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING,
                    RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

            MapProjection proj = new MapProjection(getSize());
            drawGraticule(g2, proj);
            drawBaseMap(g2, proj);
            drawSymbols(g2, proj);
            drawLegend(g2);
            drawHeader(g2);
        } finally {
            g2.dispose();
        }
    }

    private void drawGraticule(Graphics2D g2, MapProjection proj) {
        g2.setColor(GRID);
        g2.setStroke(new BasicStroke(1f));
        for (int lon = -180; lon <= 180; lon += 30) {
            Point2D.Double p = proj.projectRaw(0, lon);
            g2.drawLine((int) p.x, 0, (int) p.x, proj.height());
        }
        for (int lat = -60; lat <= 60; lat += 30) {
            Point2D.Double p = proj.projectRaw(lat, 0);
            g2.drawLine(0, (int) p.y, proj.width(), (int) p.y);
        }
    }

    private void drawBaseMap(Graphics2D g2, MapProjection proj) {
        if (baseMap == null || baseMap.polygons().isEmpty()) {
            // mapa base no disponible: sólo se muestran cuadrícula y símbolos.
            return;
        }
        g2.setColor(LAND);
        for (NaturalEarthMap.PolygonGeometry poly : baseMap.polygons()) {
            Path2D path = new Path2D.Double();
            double[][] ring = poly.ring();
            boolean first = true;
            for (double[] coord : ring) {
                Point2D.Double p = proj.projectRaw(coord[1], coord[0]);
                if (first) {
                    path.moveTo(p.x, p.y);
                    first = false;
                } else {
                    path.lineTo(p.x, p.y);
                }
            }
            path.closePath();
            g2.fill(path);
            g2.setColor(COUNTRY_OUTLINE);
            g2.setStroke(new BasicStroke(0.5f));
            g2.draw(path);
            g2.setColor(LAND);
        }
    }

    private void drawSymbols(Graphics2D g2, MapProjection proj) {
        if (symbols.isEmpty()) {
            return;
        }
        int maxCount = 1;
        for (MapSymbol s : symbols) {
            if (s.count > maxCount) {
                maxCount = s.count;
            }
        }
        for (MapSymbol s : symbols) {
            GeoPoint pt = proj.project(s.latitude, s.longitude);
            s.pixelX = pt.pixelX();
            s.pixelY = pt.pixelY();
            double ratio = Math.sqrt((double) s.count / maxCount);
            double radius = 6.0 + ratio * 14.0;
            s.radius = radius;
            g2.setComposite(AlphaComposite.getInstance(AlphaComposite.SRC_OVER, 0.65f));
            g2.setColor(s.severityColor());
            g2.fill(new Ellipse2D.Double(pt.pixelX() - radius, pt.pixelY() - radius,
                    radius * 2, radius * 2));
            g2.setComposite(AlphaComposite.SrcOver);
            g2.setColor(s.severityColor().darker());
            g2.setStroke(new BasicStroke(1.2f));
            g2.draw(new Ellipse2D.Double(pt.pixelX() - radius, pt.pixelY() - radius,
                    radius * 2, radius * 2));
            g2.setColor(TEXT);
            g2.setFont(g2.getFont().deriveFont(Font.PLAIN, 11f));
            g2.drawString(Integer.toString(s.count),
                    pt.pixelX() - 4, pt.pixelY() + 4);
        }
    }

    private void drawLegend(Graphics2D g2) {
        int x = 12;
        int y = getHeight() - 108;
        g2.setColor(LEGEND_BACKGROUND);
        g2.fillRoundRect(x, y, 230, 98, 12, 12);
        g2.setColor(TEXT);
        g2.drawRoundRect(x, y, 230, 98, 12, 12);
        g2.setFont(g2.getFont().deriveFont(Font.BOLD, 11f));
        g2.drawString("Severidad (nivel Wazuh)", x + 10, y + 16);
        g2.setFont(g2.getFont().deriveFont(Font.PLAIN, 11f));
        int ly = y + 32;
        for (int i = 0; i < SEVERITY_COLORS.length; i++) {
            g2.setColor(SEVERITY_COLORS[i]);
            g2.fill(new Ellipse2D.Double(x + 10, ly - 8, 12, 12));
            g2.setColor(TEXT);
            g2.drawString(SEVERITY_LABELS[i], x + 28, ly + 2);
            ly += 14;
        }
    }

    private void drawHeader(Graphics2D g2) {
        g2.setColor(TEXT);
        g2.setFont(g2.getFont().deriveFont(Font.BOLD, 12f));
        g2.drawString("Mapa de eventos Wazuh", 12, 18);
        if (noLocationCount > 0) {
            g2.setColor(new Color(120, 30, 30));
            g2.setFont(g2.getFont().deriveFont(Font.PLAIN, 11f));
            g2.drawString("Eventos sin ubicación: " + noLocationCount, 12, 34);
        }
        if (hoveredSymbol != null) {
            drawTooltip(g2, hoveredSymbol);
        }
        if (baseMap == null || baseMap.polygons().isEmpty()) {
            g2.setColor(new Color(120, 30, 30));
            g2.setFont(g2.getFont().deriveFont(Font.PLAIN, 11f));
            g2.drawString("Mapa base no disponible; se muestran solo símbolos y cuadrícula.",
                    12, getHeight() - 12);
        }
    }

    private void drawTooltip(Graphics2D g2, MapSymbol s) {
        String title = String.format(Locale.ROOT, "%d evento(s) @ lat %.2f, lon %.2f",
                s.count, s.latitude, s.longitude);
        String body = "Severidad máx: " + s.maxLevel
                + " · Reglas: " + (s.ruleSummary().isEmpty() ? "-" : s.ruleSummary());
        FontMetrics fm = g2.getFontMetrics();
        int w = Math.max(fm.stringWidth(title), fm.stringWidth(body)) + 16;
        int h = 36;
        int tx = Math.min(getWidth() - w - 8, s.pixelX + 12);
        int ty = Math.max(8, s.pixelY - h - 8);
        g2.setColor(new Color(255, 255, 255, 235));
        g2.fillRoundRect(tx, ty, w, h, 8, 8);
        g2.setColor(new Color(60, 60, 60));
        g2.drawRoundRect(tx, ty, w, h, 8, 8);
        g2.setColor(TEXT);
        g2.setFont(g2.getFont().deriveFont(Font.BOLD, 11f));
        g2.drawString(title, tx + 8, ty + 14);
        g2.setFont(g2.getFont().deriveFont(Font.PLAIN, 11f));
        g2.drawString(body, tx + 8, ty + 28);
    }

    /**
     * Renderiza el panel a un BufferedImage (uso headless / export). Sólo
     * válido desde el EDT. Se delega en {@link #paint(java.awt.Graphics)}
     * para garantizar que cualquier componente hijo se dibuje también.
     */
    public BufferedImage renderToImage() {
        if (!javax.swing.SwingUtilities.isEventDispatchThread()) {
            throw new IllegalStateException(
                    "renderToImage debe invocarse desde el EDT");
        }
        if (getWidth() <= 0 || getHeight() <= 0) {
            setSize(new java.awt.Dimension(800, 420));
            doLayout();
        }
        BufferedImage img = new BufferedImage(getWidth(), getHeight(),
                BufferedImage.TYPE_INT_RGB);
        Graphics2D g = img.createGraphics();
        try {
            paint(g);
        } finally {
            g.dispose();
        }
        return img;
    }

    /**
     * Exporta el panel a PNG en la ruta indicada.
     */
    public void exportPng(File file) throws IOException {
        Objects.requireNonNull(file, "file");
        BufferedImage img = renderToImage();
        ImageIO.write(img, "PNG", file);
    }

    /** Acceso de sólo lectura para diagnósticos/tests. */
    public int noLocationCount() {
        return noLocationCount;
    }

    public int symbolCount() {
        return symbols.size();
    }

    public List<MapSymbol> symbols() {
        return Collections.unmodifiableList(symbols);
    }

    /** Lista de polígonos del mapa base, para inspección en tests. */
    public List<NaturalEarthMap.PolygonGeometry> polygonsForTest() {
        return baseMap.polygons();
    }

    /**
     * Símbolo agregado para una ubicación. El radio efectivo se calcula al
     * pintar y se conserva aquí para resolver hovers.
     */
    public static final class MapSymbol {
        private final LocationKey key;
        private final List<Alert> alerts;
        private final int count;
        private final int maxLevel;
        private final String topRule;
        final double latitude;
        final double longitude;
        int pixelX;
        int pixelY;
        double radius;

        MapSymbol(LocationKey key, List<Alert> alerts) {
            this.key = key;
            this.alerts = Collections.unmodifiableList(new ArrayList<>(alerts));
            this.count = alerts.size();
            this.latitude = key.latitude;
            this.longitude = key.longitude;
            int max = 0;
            Map<String, Integer> ruleCount = new TreeMap<>();
            for (Alert a : alerts) {
                if (a.level() > max) {
                    max = a.level();
                }
                String rule = a.ruleId() == null ? "" : a.ruleId();
                ruleCount.merge(rule, 1, Integer::sum);
            }
            this.maxLevel = max;
            this.topRule = ruleCount.entrySet().stream()
                    .max(Map.Entry.comparingByValue())
                    .map(Map.Entry::getKey)
                    .orElse("");
        }

        public double latitude() {
            return latitude;
        }

        public double longitude() {
            return longitude;
        }

        public int count() {
            return count;
        }

        public int maxLevel() {
            return maxLevel;
        }

        public String topRule() {
            return topRule;
        }

        public List<Alert> alerts() {
            return alerts;
        }

        Color severityColor() {
            if (maxLevel >= 13) {
                return SEVERITY_COLORS[4];
            }
            if (maxLevel >= 10) {
                return SEVERITY_COLORS[3];
            }
            if (maxLevel >= 6) {
                return SEVERITY_COLORS[2];
            }
            if (maxLevel >= 3) {
                return SEVERITY_COLORS[1];
            }
            return SEVERITY_COLORS[0];
        }

        String ruleSummary() {
            Map<String, Integer> ruleCount = new TreeMap<>();
            for (Alert a : alerts) {
                String rule = a.ruleId() == null ? "" : a.ruleId();
                ruleCount.merge(rule, 1, Integer::sum);
            }
            StringBuilder sb = new StringBuilder();
            int emitted = 0;
            for (Map.Entry<String, Integer> e : ruleCount.entrySet()) {
                if (emitted > 0) {
                    sb.append(", ");
                }
                sb.append(e.getKey()).append('×').append(e.getValue());
                emitted++;
                if (emitted >= 3) {
                    sb.append("…");
                    break;
                }
            }
            return sb.toString();
        }
    }

    private static final class LocationKey {
        final double latitude;
        final double longitude;

        LocationKey(double latitude, double longitude) {
            this.latitude = latitude;
            this.longitude = longitude;
        }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof LocationKey)) {
                return false;
            }
            LocationKey other = (LocationKey) o;
            return Double.compare(other.latitude, latitude) == 0
                    && Double.compare(other.longitude, longitude) == 0;
        }

        @Override
        public int hashCode() {
            return Objects.hash(latitude, longitude);
        }
    }

}