package edu.up.wazuh.ui;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Carga contornos costeros y de países desde un GeoJSON de Natural Earth.
 *
 * <p>El recurso {@code maps/ne_110m_admin_0_countries.geojson} es la versión
 * pública de Natural Earth (1:110m) en dominio público. Esta clase lo lee
 * una sola vez desde el classpath y lo conserva en memoria caché; no se
 * vuelve a leer ni a parsear en cada refresh o repintado del panel.</p>
 *
 * <p>El parseo usa Gson, que ya es dependencia del módulo (las propias
 * alertas se deserializan con Gson en la hoja A).</p>
 *
 * <p>La carga usa {@link ClassLoader#getResourceAsStream(String)} con la
 * ruta <em>sin</em> slash inicial. Con {@code Class.getResourceAsStream}
 * la misma ruta se interpretaría como relativa al paquete
 * {@code edu.up.wazuh.ui} y el lookup fallaría silenciosamente.</p>
 */
public final class NaturalEarthMap {

    /**
     * Ruta del recurso classpath absoluta (sin slash inicial; apta para
     * {@code ClassLoader.getResourceAsStream}).
     */
    public static final String DEFAULT_RESOURCE = "maps/ne_110m_admin_0_countries.geojson";

    private static final Logger LOG = Logger.getLogger(NaturalEarthMap.class.getName());

    private static final AtomicReference<NaturalEarthMap> CACHE = new AtomicReference<>();

    private final List<PolygonGeometry> polygons;

    private NaturalEarthMap(List<PolygonGeometry> polygons) {
        this.polygons = polygons;
    }

    public List<PolygonGeometry> polygons() {
        return polygons;
    }

    /**
     * Carga el recurso por defecto y devuelve una instancia cacheada. La
     * primera llamada lee el classpath; las siguientes devuelven la misma
     * instancia para evitar re-parseo en cada refresh.
     */
    public static NaturalEarthMap loadDefault() {
        NaturalEarthMap cached = CACHE.get();
        if (cached != null) {
            return cached;
        }
        NaturalEarthMap loaded = load(DEFAULT_RESOURCE);
        if (CACHE.compareAndSet(null, loaded)) {
            return loaded;
        }
        return CACHE.get();
    }

    /**
     * Carga un GeoJSON de Natural Earth desde el classpath usando el
     * {@code ClassLoader} del hilo actual (sin slash inicial).
     */
    public static NaturalEarthMap load(String classpathResource) {
        if (classpathResource == null || classpathResource.isEmpty()) {
            return empty();
        }
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        if (cl == null) {
            cl = NaturalEarthMap.class.getClassLoader();
        }
        try (InputStream in = cl.getResourceAsStream(classpathResource)) {
            if (in == null) {
                LOG.log(Level.WARNING,
                        "No se encontro el recurso {0}; el mapa se mostrara vacio",
                        classpathResource);
                return empty();
            }
            return parse(in);
        } catch (IOException ex) {
            LOG.log(Level.WARNING, "No se pudo leer el recurso " + classpathResource, ex);
            return empty();
        }
    }

    private static NaturalEarthMap empty() {
        return new NaturalEarthMap(Collections.emptyList());
    }

    private static NaturalEarthMap parse(InputStream in) throws IOException {
        JsonElement root;
        try (InputStreamReader reader = new InputStreamReader(in, StandardCharsets.UTF_8)) {
            root = JsonParser.parseReader(reader);
        }
        if (root == null || !root.isJsonObject()) {
            return empty();
        }
        JsonArray features = root.getAsJsonObject().getAsJsonArray("features");
        if (features == null) {
            return empty();
        }
        List<PolygonGeometry> polygons = new ArrayList<>(features.size());
        for (JsonElement el : features) {
            if (!el.isJsonObject()) {
                continue;
            }
            JsonObject geom = el.getAsJsonObject().getAsJsonObject("geometry");
            if (geom == null) {
                continue;
            }
            String type = geom.has("type") ? geom.get("type").getAsString() : "";
            JsonArray coords = geom.has("coordinates") ? geom.getAsJsonArray("coordinates") : null;
            if (coords == null) {
                continue;
            }
            switch (type) {
                case "Polygon":
                    polygons.addAll(parsePolygon(coords));
                    break;
                case "MultiPolygon":
                    polygons.addAll(parseMultiPolygon(coords));
                    break;
                default:
                    break;
            }
        }
        return new NaturalEarthMap(Collections.unmodifiableList(polygons));
    }

    private static List<PolygonGeometry> parsePolygon(JsonArray rings) {
        List<PolygonGeometry> out = new ArrayList<>(rings.size());
        for (JsonElement ringEl : rings) {
            double[][] ring = parseRing(ringEl.getAsJsonArray());
            if (ring != null) {
                out.add(new PolygonGeometry(ring));
            }
        }
        return out;
    }

    private static List<PolygonGeometry> parseMultiPolygon(JsonArray polygons) {
        List<PolygonGeometry> out = new ArrayList<>();
        for (JsonElement polygonEl : polygons) {
            out.addAll(parsePolygon(polygonEl.getAsJsonArray()));
        }
        return out;
    }

    /** Devuelve un anillo {@code [lon, lat]}; null si está vacío. */
    private static double[][] parseRing(JsonArray ringArray) {
        if (ringArray == null || ringArray.size() == 0) {
            return null;
        }
        int n = ringArray.size();
        double[][] ring = new double[n][];
        int kept = 0;
        for (int i = 0; i < n; i++) {
            JsonElement ptEl = ringArray.get(i);
            if (!ptEl.isJsonArray()) {
                continue;
            }
            JsonArray pt = ptEl.getAsJsonArray();
            if (pt.size() < 2) {
                continue;
            }
            try {
                double lon = pt.get(0).getAsDouble();
                double lat = pt.get(1).getAsDouble();
                if (Double.isFinite(lon) && Double.isFinite(lat)) {
                    ring[kept++] = new double[]{lon, lat};
                }
            } catch (NumberFormatException ignored) {
                // descartar vértice malformado
            }
        }
        if (kept == 0) {
            return null;
        }
        if (kept == n) {
            return ring;
        }
        double[][] trimmed = new double[kept][];
        System.arraycopy(ring, 0, trimmed, 0, kept);
        return trimmed;
    }

    /**
     * Polígono simple en coordenadas geográficas (lon/lat).
     */
    public static final class PolygonGeometry {
        private final double[][] ring;

        public PolygonGeometry(double[][] ring) {
            this.ring = ring;
        }

        public double[][] ring() {
            return ring;
        }

        public int vertexCount() {
            return ring.length;
        }
    }
}