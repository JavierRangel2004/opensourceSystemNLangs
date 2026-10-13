package edu.up.wazuh.ui;

import java.awt.Dimension;
import java.awt.geom.Point2D;

/**
 * Proyección equirectangular simple para el mapa geográfico.
 *
 * <p>El PLAN exige <em>"ejes/proyección equirectangular"</em> sobre un mapa base
 * real (Natural Earth). Esta clase es deliberadamente explícita: mapea
 * longitud/latitud a coordenadas de pantalla sin deformaciones cónicas ni
 * rotaciones. La región mapeable es lon ∈ [-180, 180] y lat ∈ [-90, 90].</p>
 *
 * <p>El centro vertical del mapa se sitúa en el ecuador, no en el meridiano de
 * Greenwich, para mantener proporciones correctas. El eje Y crece hacia abajo
 * (estilo Java2D).</p>
 */
public final class MapProjection {

    private final int width;
    private final int height;
    private final double scale;

    public MapProjection(Dimension canvasSize) {
        if (canvasSize == null || canvasSize.width <= 0 || canvasSize.height <= 0) {
            throw new IllegalArgumentException("Canvas invalido: " + canvasSize);
        }
        this.width = canvasSize.width;
        this.height = canvasSize.height;
        this.scale = Math.min(width / 360.0, height / 180.0);
    }

    public int width() {
        return width;
    }

    public int height() {
        return height;
    }

    public double scale() {
        return scale;
    }

    /**
     * Proyecta (lon, lat) al espacio de pantalla.
     *
     * @return punto con coordenadas enteras alineadas al píxel.
     */
    public GeoPoint project(double latitude, double longitude) {
        double x = width / 2.0 + longitude * scale;
        double y = height / 2.0 - latitude * scale;
        return new GeoPoint(latitude, longitude, (int) Math.round(x), (int) Math.round(y));
    }

    /**
     * Versión que devuelve un punto doble (útil para polígonos).
     */
    public Point2D.Double projectRaw(double latitude, double longitude) {
        Point2D.Double p = new Point2D.Double();
        p.x = width / 2.0 + longitude * scale;
        p.y = height / 2.0 - latitude * scale;
        return p;
    }
}