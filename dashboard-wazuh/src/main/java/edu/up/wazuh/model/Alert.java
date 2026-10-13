package edu.up.wazuh.model;

import java.time.Instant;
import java.util.Objects;

/**
 * Normalized Wazuh alert. Records are immutable. Missing string fields are
 * empty strings; missing coordinates are {@code null}. The raw {@code full_log}
 * payload and any other raw data are intentionally not stored.
 */
public record Alert(
        String id,
        Instant timestamp,
        String agentId,
        String agentName,
        String ruleId,
        int level,
        String description,
        String username,
        String country,
        Double latitude,
        Double longitude,
        String integration) {

    public Alert {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(timestamp, "timestamp");
        Objects.requireNonNull(ruleId, "ruleId");
        if (level < 0 || level > 15) {
            throw new IllegalArgumentException("level out of range: " + level);
        }
        agentId = agentId == null ? "" : agentId;
        agentName = agentName == null ? "" : agentName;
        description = description == null ? "" : description;
        username = username == null ? "" : username;
        country = country == null ? "" : country;
        integration = integration == null ? "" : integration;
        if (latitude != null && (latitude.isNaN() || latitude.isInfinite()
                || latitude < -90.0 || latitude > 90.0)) {
            throw new IllegalArgumentException("latitude out of range: " + latitude);
        }
        if (longitude != null && (longitude.isNaN() || longitude.isInfinite()
                || longitude < -180.0 || longitude > 180.0)) {
            throw new IllegalArgumentException("longitude out of range: " + longitude);
        }
    }
}
