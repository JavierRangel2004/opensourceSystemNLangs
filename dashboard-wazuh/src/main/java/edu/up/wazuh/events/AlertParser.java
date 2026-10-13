package edu.up.wazuh.events;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSyntaxException;
import edu.up.wazuh.model.Alert;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.DateTimeException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.HexFormat;
import java.util.Objects;

/**
 * Parses JSON documents emitted by the Wazuh manager or its integrations into
 * a normalized {@link Alert}. Accepts both the bare root object and the
 * classic {@code {"alert": {...}}} envelope used by custom integrations.
 *
 * <p>The parser deliberately never stores the {@code full_log} or any other
 * raw payload field — only the values required by {@link Alert}. An ID that
 * the source didn't provide is computed as the SHA-256 digest of
 * {@code agentId + ":" + ruleId + ":" + epochMilli} so the same alert always
 * yields the same hash.
 *
 * <p>Throws {@link IllegalArgumentException} for invalid JSON, missing
 * timestamp, missing/invalid rule, severities outside {@code 0..15} or
 * coordinates that can't be parsed or are out of range.
 */
public final class AlertParser {

    public AlertParser() {
    }

    public Alert parse(String json) {
        Objects.requireNonNull(json, "json");
        JsonElement el;
        try {
            el = JsonParser.parseString(json);
        } catch (JsonSyntaxException e) {
            throw new IllegalArgumentException("invalid json", e);
        }
        if (el == null || !el.isJsonObject()) {
            throw new IllegalArgumentException("json root is not an object");
        }
        JsonObject root = el.getAsJsonObject();
        JsonObject body = unwrapAlert(root);

        Instant timestamp = readTimestamp(body, root);
        JsonObject rule = requireObject(body, "rule", "rule required");
        String ruleId = readNonEmptyString(rule, "id", "rule.id required");
        int level = readLevel(rule);
        String description = stringOrEmpty(rule, "description");

        JsonObject agent = objectField(body, "agent");
        String agentId = agent == null ? "" : stringOrEmpty(agent, "id");
        String agentName = agent == null ? "" : stringOrEmpty(agent, "name");

        String username = extractUsername(body);
        String country = extractCountry(body);
        Coordinate coord = extractCoordinates(body);
        if (coord.invalid) {
            throw new IllegalArgumentException("invalid coordinates");
        }

        String integration = stringOrEmpty(body, "integration");
        if (integration.isEmpty()) {
            integration = stringOrEmpty(root, "integration");
        }

        String id = stringOrEmpty(body, "id");
        if (id.isEmpty()) id = stringOrEmpty(root, "id");
        if (id.isEmpty()) {
            // Compute the deterministic ID after building the normalized Alert
            // so all normalizable fields participate in the hash.
            Alert preview = new Alert("preview", timestamp, agentId, agentName,
                    ruleId, level, description, username, country,
                    coord.latitude, coord.longitude, integration);
            id = deterministicId(preview);
        }

        return new Alert(id, timestamp, agentId, agentName, ruleId, level,
                description, username, country, coord.latitude, coord.longitude,
                integration);
    }

    private static JsonObject unwrapAlert(JsonObject root) {
        if (root.has("alert") && root.get("alert").isJsonObject()) {
            return root.getAsJsonObject("alert");
        }
        return root;
    }

    private static Instant readTimestamp(JsonObject body, JsonObject root) {
        String ts = stringOrEmpty(body, "timestamp");
        if (ts.isEmpty()) ts = stringOrEmpty(root, "timestamp");
        if (ts.isEmpty()) {
            throw new IllegalArgumentException("timestamp required");
        }
        try {
            return parseTimestamp(ts);
        } catch (DateTimeException e) {
            throw new IllegalArgumentException("invalid timestamp: " + ts, e);
        }
    }

    static Instant parseTimestamp(String raw) {
        String s = raw;
        // Wazuh emits timestamps like 2024-09-23T14:28:51.123+0000 (no colon).
        if (s.matches(".*[+-]\\d{4}$")) {
            s = s.substring(0, s.length() - 2) + ":" + s.substring(s.length() - 2);
        }
        try {
            return OffsetDateTime.parse(s, DateTimeFormatter.ISO_OFFSET_DATE_TIME)
                    .toInstant();
        } catch (DateTimeParseException ignored) {
            // fall through
        }
        if (s.endsWith("Z")) {
            try {
                return Instant.parse(s);
            } catch (DateTimeParseException ignored) {
                // fall through
            }
        }
        try {
            return LocalDateTime.parse(s, DateTimeFormatter.ISO_LOCAL_DATE_TIME)
                    .toInstant(ZoneOffset.UTC);
        } catch (DateTimeParseException ignored) {
            // fall through
        }
        throw new DateTimeException("unrecognised timestamp: " + raw);
    }

    private static int readLevel(JsonObject rule) {
        if (!rule.has("level") || rule.get("level").isJsonNull()) {
            throw new IllegalArgumentException("rule.level required");
        }
        JsonElement el = rule.get("level");
        if (!el.isJsonPrimitive()) {
            throw new IllegalArgumentException("rule.level invalid");
        }
        JsonPrimitive p = el.getAsJsonPrimitive();
        if (p.isString()) {
            String s = p.getAsString().trim();
            if (!s.matches("^-?\\d+$")) {
                throw new IllegalArgumentException("rule.level invalid");
            }
            try {
                long v = Long.parseLong(s);
                if (v < 0 || v > 15) {
                    throw new IllegalArgumentException(
                            "severity out of range");
                }
                return (int) v;
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("rule.level invalid");
            }
        }
        if (!p.isNumber()) {
            throw new IllegalArgumentException("rule.level invalid");
        }
        // Numbers must be integer-valued: reject "12.5" and scientific notation.
        String repr = p.getAsString();
        if (!repr.matches("^-?\\d+$")) {
            throw new IllegalArgumentException(
                    "rule.level not an integer");
        }
        long v;
        try {
            v = Long.parseLong(repr);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("rule.level invalid");
        }
        if (v < 0 || v > 15) {
            throw new IllegalArgumentException("severity out of range");
        }
        if (v != (int) v) {
            throw new IllegalArgumentException("rule.level not an integer");
        }
        return (int) v;
    }

    private static JsonObject requireObject(JsonObject obj, String field, String message) {
        JsonElement el = obj.get(field);
        if (el == null || !el.isJsonObject()) {
            throw new IllegalArgumentException(message);
        }
        return el.getAsJsonObject();
    }

    private static JsonObject objectField(JsonObject obj, String field) {
        if (obj == null) return null;
        JsonElement el = obj.get(field);
        if (el == null || !el.isJsonObject()) return null;
        return el.getAsJsonObject();
    }

    private static String readNonEmptyString(JsonObject obj, String field, String message) {
        if (obj == null || !obj.has(field) || obj.get(field).isJsonNull()) {
            throw new IllegalArgumentException(message);
        }
        JsonElement el = obj.get(field);
        if (!el.isJsonPrimitive()) {
            throw new IllegalArgumentException(message);
        }
        String s = el.getAsString().trim();
        if (s.isEmpty()) {
            throw new IllegalArgumentException(message);
        }
        return s;
    }

    private static String stringOrEmpty(JsonObject obj, String field) {
        if (obj == null || !obj.has(field) || obj.get(field).isJsonNull()) return "";
        JsonElement el = obj.get(field);
        if (el.isJsonPrimitive()) return el.getAsString().trim();
        if (el.isJsonObject()) return el.toString();
        if (el.isJsonArray()) return el.toString();
        return "";
    }

    /**
     * Extracts a username from typical Windows / Unix event shapes.
     *
     * <p>Order of preference:
     * <ol>
     *   <li>{@code data.srcuser}, {@code data.dstuser}, {@code data.user},
     *       {@code data.username} (Unix-style); the placeholder
     *       {@code "-"} is skipped so a later non-empty value can win.</li>
     *   <li>{@code data.win.eventdata.targetUserName} (Windows-style) and
     *       {@code subjectUserName}. When {@code targetDomainName} (or
     *       {@code subjectDomainName}) is present, the result is returned as
     *       a "DOMAIN-backslash-user" string so the LDAP lookup can match it.</li>
     *   <li>The legacy root-level {@code win.eventdata.targetUserName},
     *       again with domain preservation.</li>
     * </ol>
     */
    private static String extractUsername(JsonObject body) {
        JsonObject data = objectField(body, "data");
        if (data != null) {
            for (String field : new String[]{"srcuser", "dstuser", "user", "username"}) {
                String u = stringOrEmpty(data, field);
                if (isRealUsername(u)) return u;
            }
            String winUser = windowsEventdataUsername(objectField(data, "win"));
            if (winUser != null) return winUser;
        }
        String winUser = windowsEventdataUsername(objectField(body, "win"));
        if (winUser != null) return winUser;
        return "";
    }

    private static boolean isRealUsername(String u) {
        return u != null && !u.isEmpty() && !"-".equals(u);
    }

    private static String windowsEventdataUsername(JsonObject win) {
        if (win == null) return null;
        JsonObject ev = objectField(win, "eventdata");
        if (ev == null) return null;
        // Pick one user field; the domain field must be the *paired* one.
        // Mixing targetUserName with subjectDomainName (or vice versa) is a
        // known miscorrelation that we reject by selecting the pair
        // together.
        String user = stringOrEmpty(ev, "targetUserName");
        String userField = "targetUserName";
        if (!isRealUsername(user)) {
            String subject = stringOrEmpty(ev, "subjectUserName");
            if (isRealUsername(subject)) {
                user = subject;
                userField = "subjectUserName";
            }
        }
        if (!isRealUsername(user)) return null;
        // Pair the chosen user field with its matching domain field.
        // targetUserName pairs with targetDomainName; subjectUserName
        // pairs with subjectDomainName. Mixing the two is a documented
        // mis-correlation we explicitly avoid.
        String domainField = "targetUserName".equals(userField)
                ? "targetDomainName" : "subjectDomainName";
        String domain = stringOrEmpty(ev, domainField);
        // The "-" placeholder must not be prefixed onto the user: it's
        // either an explicit no-domain value or a malformed payload. We
        // simply skip the prefix and return the bare user.
        if (domain.isEmpty() || "-".equals(domain) || user.contains("\\")) {
            return user;
        }
        return domain + "\\" + user;
    }

    private static String extractCountry(JsonObject body) {
        JsonObject geo = findGeoObject(body);
        if (geo != null) {
            String country = findStringCaseInsensitive(geo, "country_name");
            if (!country.isEmpty()) return country;
            country = findStringCaseInsensitive(geo, "country");
            if (!country.isEmpty()) return country;
            country = findStringCaseInsensitive(geo, "city_name");
            if (!country.isEmpty()) return country;
        }
        return stringOrEmpty(body, "country");
    }

    /**
     * Finds the geographic location object regardless of where the
     * integration nests it. Looks for {@code geoLocation} /
     * {@code GeoLocation} at the body root and inside {@code data}, plus a
     * {@code location.geo} fallback. The lookup is case-insensitive to
     * accommodate both the manager and the indexer payload conventions.
     */
    private static JsonObject findGeoObject(JsonObject body) {
        JsonObject o = caseInsensitiveObjectField(body, "geolocation");
        if (o != null) return o;
        JsonObject location = objectField(body, "location");
        if (location != null) {
            JsonObject nested = caseInsensitiveObjectField(location, "geo");
            if (nested != null) return nested;
            return location;
        }
        JsonObject data = objectField(body, "data");
        if (data != null) {
            JsonObject nested = caseInsensitiveObjectField(data, "geolocation");
            if (nested != null) return nested;
        }
        return null;
    }

    private static JsonObject caseInsensitiveObjectField(JsonObject obj, String field) {
        if (obj == null) return null;
        for (java.util.Map.Entry<String, JsonElement> e : obj.entrySet()) {
            if (e.getKey().equalsIgnoreCase(field)) {
                if (e.getValue() != null && e.getValue().isJsonObject()) {
                    return e.getValue().getAsJsonObject();
                }
                return null;
            }
        }
        return null;
    }

    private static String findStringCaseInsensitive(JsonObject obj, String field) {
        if (obj == null) return "";
        for (java.util.Map.Entry<String, JsonElement> e : obj.entrySet()) {
            if (e.getKey().equalsIgnoreCase(field)) {
                JsonElement el = e.getValue();
                if (el == null || el.isJsonNull()) return "";
                if (el.isJsonPrimitive()) return el.getAsString().trim();
                return el.toString();
            }
        }
        return "";
    }

    private static Coordinate extractCoordinates(JsonObject body) {
        JsonObject geo = findGeoObject(body);
        if (geo == null) {
            return new Coordinate(null, null, false);
        }
        Double lat = findDoubleCaseInsensitive(geo, "latitude");
        Double lon = findDoubleCaseInsensitive(geo, "longitude");
        if ((lat == null) != (lon == null)) {
            return new Coordinate(null, null, true);
        }
        if (lat == null) {
            return new Coordinate(null, null, false);
        }
        if (lat.isNaN() || lat.isInfinite()) return new Coordinate(null, null, true);
        if (lon.isNaN() || lon.isInfinite()) return new Coordinate(null, null, true);
        if (lat < -90.0 || lat > 90.0) return new Coordinate(null, null, true);
        if (lon < -180.0 || lon > 180.0) return new Coordinate(null, null, true);
        return new Coordinate(lat, lon, false);
    }

    private static Double findDoubleCaseInsensitive(JsonObject obj, String field) {
        if (obj == null) return null;
        for (java.util.Map.Entry<String, JsonElement> e : obj.entrySet()) {
            if (e.getKey().equalsIgnoreCase(field)) {
                return readDoubleValue(e.getValue());
            }
        }
        return null;
    }

    private static Double readDoubleValue(JsonElement el) {
        if (el == null || el.isJsonNull()) return null;
        if (!el.isJsonPrimitive()) return Double.NaN;
        JsonPrimitive p = el.getAsJsonPrimitive();
        if (p.isNumber()) {
            try {
                return p.getAsDouble();
            } catch (NumberFormatException e) {
                return Double.NaN;
            }
        }
        try {
            return Double.parseDouble(p.getAsString().trim());
        } catch (NumberFormatException e) {
            return Double.NaN;
        }
    }

    /**
     * Deterministic, payload-free identifier. SHA-256 of every normalized
     * alert field — agentId, ruleId, epoch milli, username, country, latitude,
     * longitude, description and integration — truncated to 32 hex chars.
     * The hash is stable across runs but never derived from {@code full_log}
     * or any other raw payload that may carry secrets. Including all
     * normalized fields avoids collisions between distinct events that
     * share only an agent/rule/timestamp triple.
     */
    static String deterministicId(Alert a) {
        StringBuilder sb = new StringBuilder(256);
        sb.append(nullSafe(a.agentId())).append('|');
        sb.append(nullSafe(a.ruleId())).append('|');
        sb.append(a.timestamp().toEpochMilli()).append('|');
        sb.append(nullSafe(a.username())).append('|');
        sb.append(nullSafe(a.description())).append('|');
        sb.append(nullSafe(a.country())).append('|');
        sb.append(a.latitude() == null ? "" : a.latitude().toString())
                .append('|');
        sb.append(a.longitude() == null ? "" : a.longitude().toString())
                .append('|');
        sb.append(nullSafe(a.integration()));
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(sb.toString().getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest).substring(0, 32);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is mandatory in modern JDKs.
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private static String nullSafe(String s) {
        return s == null ? "" : s;
    }

    /** Internal coordinate triple returned by {@link #extractCoordinates}. */
    private static final class Coordinate {
        final Double latitude;
        final Double longitude;
        final boolean invalid;

        Coordinate(Double latitude, Double longitude, boolean invalid) {
            this.latitude = latitude;
            this.longitude = longitude;
            this.invalid = invalid;
        }
    }
}
