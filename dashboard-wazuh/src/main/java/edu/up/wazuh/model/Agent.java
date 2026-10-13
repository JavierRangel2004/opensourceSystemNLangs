package edu.up.wazuh.model;

import java.util.Objects;

/**
 * Normalized Wazuh agent descriptor.
 */
public record Agent(
        String id,
        String name,
        String status,
        String ip,
        String os) {

    public Agent {
        Objects.requireNonNull(id, "id");
        name = name == null ? "" : name;
        status = status == null ? "" : status;
        ip = ip == null ? "" : ip;
        os = os == null ? "" : os;
    }
}
