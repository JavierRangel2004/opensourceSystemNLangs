package edu.up.wazuh.app;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Objects;

/**
 * Almacena el token Bearer del webhook generado en tiempo de ejecución.
 * El token nunca se imprime ni se persiste; sólo se expone mediante {@link #headerValue()}
 * para que el emisor interno (smoke) o el script externo lo conozca.
 *
 * <p>El script externo debe leerlo por canal seguro (variable de entorno o parámetro de
 * invocación) y nunca por logs ni trazas.
 */
public final class TokenStore {

    private final String token;
    private final boolean generatedRuntime;

    public TokenStore(String existingToken) {
        if (existingToken != null && !existingToken.isBlank()) {
            this.token = existingToken;
            this.generatedRuntime = false;
        } else {
            this.token = generateRandom();
            this.generatedRuntime = true;
        }
    }

    public String token() { return token; }
    public boolean generatedRuntime() { return generatedRuntime; }

    public String headerValue() {
        return "Bearer " + token;
    }

    public boolean matches(String authorizationHeader) {
        if (authorizationHeader == null) return false;
        String h = authorizationHeader.trim();
        if (!h.regionMatches(true, 0, "Bearer ", 0, 7)) return false;
        String presented = h.substring(7).trim();
        return constantTimeEquals(presented, token);
    }

    private static String generateRandom() {
        byte[] buf = new byte[32];
        new SecureRandom().nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        byte[] ba = a.getBytes();
        byte[] bb = b.getBytes();
        if (ba.length != bb.length) return false;
        int diff = 0;
        for (int i = 0; i < ba.length; i++) diff |= ba[i] ^ bb[i];
        return diff == 0;
    }

    @Override
    public String toString() {
        return "TokenStore{generated=" + generatedRuntime + ", length=" + (token == null ? 0 : token.length()) + "}";
    }

    @Override
    public int hashCode() { return Objects.hashCode(token); }

    @Override
    public boolean equals(Object other) {
        return other instanceof TokenStore t && Objects.equals(t.token, token);
    }
}