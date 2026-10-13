package edu.up.wazuh.ldap;

import edu.up.wazuh.model.DirectoryUser;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import java.net.URI;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * JNDI-backed {@link DirectoryLookup}. Creates a fresh
 * {@link InitialDirContext} per {@link #find(String)} call, sets explicit
 * connect / read timeouts, disables referral chasing, caps the per-search
 * result count and limits the requested attributes to the small allow-list
 * required by {@link DirectoryUser}.
 *
 * <p>The constructor enforces a small set of security rules on the URL:
 * <ul>
 *   <li>the scheme must be {@code ldap://} or {@code ldaps://};</li>
 *   <li>{@code ldap://} is only acceptable when the host is a strict
 *       loopback literal (IPv4 127.0.0.0/8, {@code ::1}, or
 *       {@code localhost});</li>
 *   <li>the URL must not carry a user-info component, a query, or a
 *       fragment, and a host must be present.</li>
 * </ul>
 * Failure to satisfy any of these throws {@link IllegalArgumentException}.
 * Exception messages never echo the URL — the URL could carry credentials
 * in its user-info component.
 *
 * <p>Search dispatch:
 * <ul>
 *   <li>{@code user@domain} inputs match {@code userPrincipalName} only.</li>
 *   <li>{@code DOMAIN-backslash-user} inputs strip the prefix and match
 *       {@code sAMAccountName} only. The NetBIOS domain is not inferred
 *       from the configured base DN; that correlation must be confirmed
 *       against the deployment's directory layout.</li>
 *   <li>{@code user} inputs match {@code sAMAccountName} only.</li>
 * </ul>
 * No OR is performed across {@code sAMAccountName} and
 * {@code userPrincipalName}; doing so is a known mis-correlation that
 * returns the wrong record when UPN and sAM resolve to different entries.
 *
 * <p>{@link SearchControls#setCountLimit(long)} is set to {@code 2}: if
 * the directory returns a second entry under the configured base DN that
 * matches the same sAM, the lookup fails fast with a sanitized
 * {@link NamingException} rather than silently returning the first one.
 */
public class JndiDirectoryLookup implements DirectoryLookup {

    static final String CONNECT_TIMEOUT_MS = "5000";
    static final String READ_TIMEOUT_MS = "5000";
    /**
     * Maximum entries returned by JNDI per search. A returned count of
     * {@code 2} signals "more than expected"; the lookup is then treated
     * as ambiguous and rejected.
     */
    static final long DUPLICATE_GUARD_COUNT = 2L;

    private static final String[] ALLOWED_ATTRIBUTES = {
            "displayName", "mail", "department"
    };

    private final String url;
    private final String bindDn;
    private final char[] password;
    private final String baseDn;

    public JndiDirectoryLookup(String url, String bindDn, String password, String baseDn) {
        Objects.requireNonNull(url, "url");
        Objects.requireNonNull(baseDn, "baseDn");
        validateUrl(url);
        this.url = url;
        this.bindDn = bindDn == null ? "" : bindDn;
        this.password = password == null ? new char[0] : password.toCharArray();
        this.baseDn = baseDn;
    }

    private static void validateUrl(String url) {
        URI uri;
        try {
            uri = URI.create(url);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("invalid LDAP url");
        }
        String scheme = uri.getScheme();
        if (scheme == null) {
            throw new IllegalArgumentException("LDAP url scheme required");
        }
        if ("ldaps".equalsIgnoreCase(scheme)) {
            // OK for any host
        } else if ("ldap".equalsIgnoreCase(scheme)) {
            String host = uri.getHost();
            if (host != null && host.length() >= 2
                    && host.charAt(0) == '[' && host.charAt(host.length() - 1) == ']') {
                host = host.substring(1, host.length() - 1);
            }
            if (!isLoopbackHost(host)) {
                throw new IllegalArgumentException(
                        "plain LDAP only allowed for loopback addresses");
            }
        } else {
            throw new IllegalArgumentException("unsupported LDAP scheme");
        }
        if (uri.getHost() == null) {
            throw new IllegalArgumentException("LDAP url host required");
        }
        if (uri.getUserInfo() != null) {
            throw new IllegalArgumentException("LDAP url userinfo forbidden");
        }
        if (uri.getQuery() != null) {
            throw new IllegalArgumentException("LDAP url query forbidden");
        }
        if (uri.getFragment() != null) {
            throw new IllegalArgumentException("LDAP url fragment forbidden");
        }
    }

    /** Strict loopback detection (no DNS lookups). */
    static boolean isLoopbackHost(String host) {
        if (host == null || host.isEmpty()) return false;
        if ("localhost".equalsIgnoreCase(host)) return true;
        if ("::1".equals(host) || "0:0:0:0:0:0:0:1".equalsIgnoreCase(host)) return true;
        String[] parts = host.split("\\.", -1);
        if (parts.length != 4) return false;
        int[] octets = new int[4];
        for (int i = 0; i < 4; i++) {
            String p = parts[i];
            if (p.isEmpty() || p.length() > 3) return false;
            int v = 0;
            for (int j = 0; j < p.length(); j++) {
                char c = p.charAt(j);
                if (c < '0' || c > '9') return false;
                v = v * 10 + (c - '0');
                if (v > 255) return false;
            }
            octets[i] = v;
        }
        return octets[0] == 127;
    }

    @Override
    public Optional<DirectoryUser> find(String username) throws Exception {
        if (username == null) return Optional.empty();
        String trimmed = username.trim();
        if (trimmed.isEmpty() || "-".equals(trimmed)) {
            return Optional.empty();
        }

        String filter = buildFilter(trimmed);
        if (filter == null) return Optional.empty();

        Hashtable<String, Object> env = baseEnvironment();
        InitialDirContext ctx = new InitialDirContext(env);
        try {
            SearchControls controls = new SearchControls();
            controls.setReturningAttributes(ALLOWED_ATTRIBUTES);
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            // Cap results at 2 so that a duplicate sAM yields a sane,
            // explicit failure instead of silently picking the first hit.
            controls.setCountLimit(DUPLICATE_GUARD_COUNT);

            NamingEnumeration<SearchResult> results = ctx.search(
                    baseDn, filter, controls);
            try {
                List<SearchResult> matched = new ArrayList<>(2);
                while (results.hasMore()) {
                    matched.add(results.next());
                    if (matched.size() >= 2) {
                        // Reached the configured guard; consume the rest
                        // to keep the enumeration state well-defined.
                        while (results.hasMore()) {
                            matched.add(results.next());
                        }
                        break;
                    }
                }
                if (matched.isEmpty()) {
                    return Optional.empty();
                }
                if (matched.size() > 1) {
                    throw new NamingException(
                            "ambiguous directory match for input");
                }
                Attributes attrs = matched.get(0).getAttributes();
                return Optional.of(new DirectoryUser(
                        username,
                        attrString(attrs, "displayName"),
                        attrString(attrs, "mail"),
                        attrString(attrs, "department")));
            } finally {
                if (results != null) results.close();
            }
        } finally {
            ctx.close();
        }
    }

    /**
     * Selects exactly one search filter for the input style. UPN inputs
     * resolve against {@code userPrincipalName}; everything else resolves
     * against {@code sAMAccountName} (with the {@code DOMAIN\} prefix
     * stripped). The filter is RFC 4515 escaped; returns {@code null}
     * for inputs that cannot be turned into a usable search.
     */
    static String buildFilter(String input) {
        if (input.indexOf('@') >= 0) {
            // UPN — single attribute, no sAM attempt.
            return "(userPrincipalName=" + Rfc4515.escape(input) + ")";
        }
        int slash = input.indexOf('\\');
        String sam = slash >= 0
                ? input.substring(slash + 1).trim()
                : input.trim();
        if (sam.isEmpty()) return null;
        return "(sAMAccountName=" + Rfc4515.escape(sam) + ")";
    }

    private Hashtable<String, Object> baseEnvironment() {
        Hashtable<String, Object> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, url);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, bindDn);
        env.put(Context.SECURITY_CREDENTIALS, new String(password));
        env.put("com.sun.jndi.ldap.connect.timeout", CONNECT_TIMEOUT_MS);
        env.put("com.sun.jndi.ldap.read.timeout", READ_TIMEOUT_MS);
        env.put(Context.REFERRAL, "ignore");
        return env;
    }

    private static String attrString(Attributes attrs, String name) {
        if (attrs == null) return "";
        Attribute attr = attrs.get(name);
        if (attr == null || attr.size() == 0) return "";
        try {
            Object value = attr.get();
            return value == null ? "" : value.toString();
        } catch (Exception e) {
            return "";
        }
    }

    @Override
    public String toString() {
        return "JndiDirectoryLookup{id=" + System.identityHashCode(this) + "}";
    }
}
