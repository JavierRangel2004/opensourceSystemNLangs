package edu.up.wazuh.ui;

import java.util.Objects;

/**
 * Punto geográfico proyectado al espacio de pantalla de {@link GeoMapPanel}.
 *
 * <p>Mantiene latitud/longitud y sus equivalentes en píxeles tras la proyección
 * equirectangular. La clase es inmutable y forma parte del paquete {@code ui}
 * para evitar depender de tipos geográficos que el contrato no entrega.</p>
 *
 * <p>Coordenadas inválidas (NaN, infinitas o fuera de rango) se rechazan en el
 * constructor para impedir símbolos colocados de forma arbitraria, según la regla
 * del PLAN: <em>"sin geolocalización inventada"</em>.</p>
 */
public final class GeoPoint {

    private final double latitude;
    private final double longitude;
    private final int pixelX;
    private final int pixelY;

    public GeoPoint(double latitude, double longitude, int pixelX, int pixelY) {
        if (Double.isNaN(latitude) || Double.isNaN(longitude)
                || Double.isInfinite(latitude) || Double.isInfinite(longitude)) {
            throw new IllegalArgumentException("Coordenadas invalidas: lat=" + latitude + " lon=" + longitude);
        }
        if (latitude < -90.0 || latitude > 90.0) {
            throw new IllegalArgumentException("Latitud fuera de rango: " + latitude);
        }
        if (longitude < -180.0 || longitude > 180.0) {
            throw new IllegalArgumentException("Longitud fuera de rango: " + longitude);
        }
        this.latitude = latitude;
        this.longitude = longitude;
        this.pixelX = pixelX;
        this.pixelY = pixelY;
    }

    public double latitude() {
        return latitude;
    }

    public double longitude() {
        return longitude;
    }

    public int pixelX() {
        return pixelX;
    }

    public int pixelY() {
        return pixelY;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof GeoPoint)) {
            return false;
        }
        GeoPoint other = (GeoPoint) o;
        return Double.compare(other.latitude, latitude) == 0
                && Double.compare(other.longitude, longitude) == 0
                && other.pixelX == pixelX
                && other.pixelY == pixelY;
    }

    @Override
    public int hashCode() {
        return Objects.hash(latitude, longitude, pixelX, pixelY);
    }

    @Override
    public String toString() {
        return "GeoPoint{lat=" + latitude + ", lon=" + longitude
                + ", px=(" + pixelX + "," + pixelY + ")}";
    }
}