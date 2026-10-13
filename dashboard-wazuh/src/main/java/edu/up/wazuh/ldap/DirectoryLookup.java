package edu.up.wazuh.ldap;

import edu.up.wazuh.model.DirectoryUser;

import java.util.Optional;

/**
 * Looks up directory users by identifier. Implementations may search an LDAP
 * server, an in-memory stand-in, or any other source as long as the contract
 * is honored.
 */
public interface DirectoryLookup extends AutoCloseable {

    /**
     * Resolves {@code username} to a {@link DirectoryUser}. Returns
     * {@link Optional#empty()} for placeholder values ({@code "-"}, empty or
     * blank input) without issuing a search.
     *
     * <p>Implementations may throw any exception when the underlying service
     * is unreachable; callers are expected to surface that to the user with
     * the appropriate fallback status.
     */
    Optional<DirectoryUser> find(String username) throws Exception;

    @Override
    default void close() {
        // No-op by default; implementations may close pooled resources.
    }
}
