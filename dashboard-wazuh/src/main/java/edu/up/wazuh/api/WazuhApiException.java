package edu.up.wazuh.api;

import java.io.IOException;

/**
 * Signals a Wazuh API error without leaking response bodies, headers, URLs or
 * credentials. Only the HTTP status and a coarse reason are exposed.
 */
public class WazuhApiException extends IOException {

    private static final long serialVersionUID = 1L;

    private final int statusCode;
    private final String reason;

    public WazuhApiException(int statusCode, String reason) {
        super("Wazuh API error status=" + statusCode + " reason=" + reason);
        this.statusCode = statusCode;
        this.reason = reason == null ? "unknown" : reason;
    }

    public int statusCode() {
        return statusCode;
    }

    public String reason() {
        return reason;
    }

    @Override
    public String toString() {
        return "WazuhApiException{status=" + statusCode + ", reason=" + reason + "}";
    }
}
