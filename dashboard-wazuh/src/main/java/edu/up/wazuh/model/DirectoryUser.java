package edu.up.wazuh.model;

/**
 * Normalized directory user returned by {@link edu.up.wazuh.ldap.DirectoryLookup}.
 * Fields may be empty when the underlying LDAP server did not return them.
 */
public record DirectoryUser(
        String username,
        String displayName,
        String email,
        String department) {

    public DirectoryUser {
        username = username == null ? "" : username;
        displayName = displayName == null ? "" : displayName;
        email = email == null ? "" : email;
        department = department == null ? "" : department;
    }
}
