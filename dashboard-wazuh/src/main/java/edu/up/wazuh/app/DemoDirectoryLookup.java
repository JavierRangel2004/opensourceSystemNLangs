package edu.up.wazuh.app;

import edu.up.wazuh.ldap.DirectoryLookup;
import edu.up.wazuh.model.DirectoryUser;

import java.util.Optional;

/**
 * Lookup SINTÉTICO para el modo demo. Devuelve un {@link DirectoryUser} construido
 * a partir del nombre de usuario recibido, marcado explícitamente como
 * "DEMO" para evitar confusiones con el AD/LDAPS institucional.
 *
 * <p>Esta clase <strong>no contacta</strong> ningún directorio real. Existe sólo
 * para que el modo demo muestre el camino "found" sin claim de LDAP real.</p>
 */
public final class DemoDirectoryLookup implements DirectoryLookup {

    public static final String DEMO_DEPARTMENT = "DEMO";
    public static final String DEMO_EMAIL_DOMAIN = "demo.invalid";

    @Override
    public Optional<DirectoryUser> find(String username) {
        if (username == null || username.isBlank()) return Optional.empty();
        String displayName = username + " (DEMO)";
        String email = username + "@" + DEMO_EMAIL_DOMAIN;
        return Optional.of(new DirectoryUser(username, displayName, email, DEMO_DEPARTMENT));
    }

    @Override
    public void close() {
        // No-op: no hay recursos externos.
    }
}