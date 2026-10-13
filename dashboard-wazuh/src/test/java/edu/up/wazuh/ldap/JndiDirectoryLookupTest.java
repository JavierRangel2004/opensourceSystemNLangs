package edu.up.wazuh.ldap;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldif.LDIFException;
import edu.up.wazuh.model.DirectoryUser;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import javax.naming.NamingException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class JndiDirectoryLookupTest {

    private static final String BASE_DN = "dc=example,dc=com";
    private static final String BIND_DN = "cn=admin," + BASE_DN;
    private static final String BIND_PW = "admin-pw";

    private InMemoryDirectoryServer server;
    private int port;

    @BeforeAll
    void setupServer() throws LDAPException, LDIFException, UnknownHostException {
        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(BASE_DN);
        // Disable schema enforcement so any attribute set is valid in tests;
        // real deployments keep schema checks on.
        config.setSchema(null);
        InMemoryListenerConfig cfg = InMemoryListenerConfig.createLDAPConfig(
                "test", InetAddress.getByName("127.0.0.1"), 0, null);
        config.setListenerConfigs(cfg);
        InMemoryDirectoryServer ds = new InMemoryDirectoryServer(config);
        ds.add("dn: " + BASE_DN, "objectClass: top", "objectClass: domain", "dc: example");
        // Bind entry must carry a valid objectClass so JNDI can authenticate
        // against it.
        ds.add("dn: " + BIND_DN,
                "objectClass: top",
                "objectClass: person",
                "objectClass: organizationalPerson",
                "objectClass: inetOrgPerson",
                "cn: admin",
                "userPassword: " + BIND_PW);
        ds.add("dn: uid=alice," + BASE_DN,
                "objectClass: top",
                "objectClass: person",
                "objectClass: organizationalPerson",
                "objectClass: inetOrgPerson",
                "uid: alice",
                "cn: Alice Anderson",
                "displayName: Alice Anderson",
                "mail: alice@example.com",
                "departmentNumber: 12",
                "department: IT",
                "sAMAccountName: alice",
                "userPrincipalName: alice@example.com");
        ds.add("dn: uid=bob," + BASE_DN,
                "objectClass: top",
                "objectClass: person",
                "objectClass: organizationalPerson",
                "objectClass: inetOrgPerson",
                "uid: bob",
                "cn: Bob Brown",
                "displayName: Bob Brown",
                "mail: bob@example.com",
                "department: Finance",
                "sAMAccountName: bob",
                "userPrincipalName: bob@example.com");
        ds.add("dn: uid=carol," + BASE_DN,
                "objectClass: top",
                "objectClass: person",
                "objectClass: organizationalPerson",
                "objectClass: inetOrgPerson",
                "uid: carol",
                "cn: Carol Curtis",
                "displayName: Carol Curtis",
                "mail: carol@example.com",
                "department: HR",
                // Carol is the unique owner of this UPN; another entry's
                // sAMAccountName collides with it.
                "sAMAccountName: carol",
                "userPrincipalName: carol@example.com");
        ds.add("dn: uid=carol-collision," + BASE_DN,
                "objectClass: top",
                "objectClass: person",
                "objectClass: organizationalPerson",
                "objectClass: inetOrgPerson",
                "uid: carol-collision",
                "cn: Carol Collision",
                "sAMAccountName: carol@example.com",
                "userPrincipalName: other@example.com");
        // Two entries with the same sAMAccountName in the BASE_DN — the
        // configured guard must reject the lookup.
        ds.add("dn: uid=dup1," + BASE_DN,
                "objectClass: top",
                "objectClass: person",
                "objectClass: organizationalPerson",
                "objectClass: inetOrgPerson",
                "uid: dup1",
                "cn: Dup One",
                "sAMAccountName: shared");
        ds.add("dn: uid=dup2," + BASE_DN,
                "objectClass: top",
                "objectClass: person",
                "objectClass: organizationalPerson",
                "objectClass: inetOrgPerson",
                "uid: dup2",
                "cn: Dup Two",
                "sAMAccountName: shared");
        ds.startListening();
        server = ds;
        port = ds.getListenPort();
    }

    @AfterAll
    void tearDown() {
        if (server != null) {
            server.shutDown(true);
            server = null;
        }
    }

    private JndiDirectoryLookup newLookup() {
        return new JndiDirectoryLookup(
                "ldap://127.0.0.1:" + port, BIND_DN, BIND_PW, BASE_DN);
    }

    @Test
    void binds_and_returns_dnUser_when_present() throws Exception {
        JndiDirectoryLookup lookup = newLookup();
        try {
            Optional<DirectoryUser> alice = lookup.find("alice");
            assertTrue(alice.isPresent());
            assertEquals("alice@example.com", alice.get().email());
            assertEquals("IT", alice.get().department());
            assertEquals("Alice Anderson", alice.get().displayName());
            assertEquals("alice", alice.get().username());
        } finally {
            lookup.close();
        }
    }

    @Test
    void returns_empty_when_user_absent() throws Exception {
        JndiDirectoryLookup lookup = newLookup();
        try {
            assertFalse(lookup.find("nobody").isPresent());
        } finally {
            lookup.close();
        }
    }

    @Test
    void bypasses_lookup_for_placeholder_values() throws Exception {
        JndiDirectoryLookup lookup = newLookup();
        try {
            assertFalse(lookup.find("-").isPresent());
            assertFalse(lookup.find("   ").isPresent());
            assertFalse(lookup.find("").isPresent());
            assertFalse(lookup.find(null).isPresent());
        } finally {
            lookup.close();
        }
    }

    @Test
    void resolves_upn_using_userPrincipalName_only() throws Exception {
        // UPN inputs must match userPrincipalName only. The search must not
        // also try sAMAccountName — doing so would correlate the wrong
        // record when UPN and sAM point to different entries.
        JndiDirectoryLookup lookup = newLookup();
        try {
            Optional<DirectoryUser> carol = lookup.find("carol@example.com");
            assertTrue(carol.isPresent());
            assertEquals("carol@example.com", carol.get().username());
            assertEquals("HR", carol.get().department());
        } finally {
            lookup.close();
        }
    }


    @Test
    void resolves_user_over_bracketed_ipv6_loopback() throws Exception {
        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig(BASE_DN);
        config.setSchema(null);
        config.setListenerConfigs(InMemoryListenerConfig.createLDAPConfig(
                "ipv6", InetAddress.getByName("::1"), 0, null));
        try (InMemoryDirectoryServer ipv6 = new InMemoryDirectoryServer(config)) {
            ipv6.restoreSnapshot(server.createSnapshot());
            ipv6.startListening();
            try (JndiDirectoryLookup lookup = new JndiDirectoryLookup(
                    "ldap://[::1]:" + ipv6.getListenPort("ipv6"), BIND_DN, BIND_PW, BASE_DN)) {
                DirectoryUser user = lookup.find("alice").orElseThrow();
                assertEquals("alice@example.com", user.email());
                assertEquals("IT", user.department());
            }
        }
    }

    @Test
    void resolves_domain_backslash_user_against_sAMAccountName() throws Exception {
        JndiDirectoryLookup lookup = newLookup();
        try {
            Optional<DirectoryUser> alice = lookup.find("EXAMPLE" + "\\" + "alice");
            assertTrue(alice.isPresent());
            assertEquals("EXAMPLE" + "\\" + "alice", alice.get().username());
        } finally {
            lookup.close();
        }
    }

    @Test
    void fails_when_two_directory_entries_share_sAMAccountName() throws Exception {
        // The configured guard (countLimit=2) must make the lookup refuse
        // silently-returning the first hit when a duplicate sAM exists.
        JndiDirectoryLookup lookup = newLookup();
        try {
            NamingException ex = assertThrows(NamingException.class,
                    () -> lookup.find("shared"));
            assertFalse(ex.getMessage() == null || ex.getMessage().isEmpty(),
                    "exception must carry a sane reason");
        } finally {
            lookup.close();
        }
    }

    @Test
    void constructor_rejects_plain_ldap_outside_loopback() {
        assertThrows(IllegalArgumentException.class,
                () -> new JndiDirectoryLookup("ldap://example.com:389",
                        BIND_DN, BIND_PW, BASE_DN));
    }

    @Test
    void constructor_rejects_non_numeric_hostname_starting_with_127() {
        assertThrows(IllegalArgumentException.class,
                () -> new JndiDirectoryLookup("ldap://127.attacker.example:389",
                        BIND_DN, BIND_PW, BASE_DN));
    }

    @Test
    void constructor_accepts_ldaps_for_any_host() {
        new JndiDirectoryLookup("ldaps://example.com:636",
                BIND_DN, BIND_PW, BASE_DN);
    }

    @Test
    void constructor_rejects_unsupported_scheme() {
        assertThrows(IllegalArgumentException.class,
                () -> new JndiDirectoryLookup("http://127.0.0.1:389",
                        BIND_DN, BIND_PW, BASE_DN));
    }

    @Test
    void constructor_rejects_url_with_userinfo() {
        assertThrows(IllegalArgumentException.class,
                () -> new JndiDirectoryLookup(
                        "ldap://" + "hidden-user" + ":hidden-pass@127.0.0.1:389",
                        BIND_DN, BIND_PW, BASE_DN));
        assertThrows(IllegalArgumentException.class,
                () -> new JndiDirectoryLookup(
                        "ldap://attacker@127.0.0.1:389",
                        BIND_DN, BIND_PW, BASE_DN));
    }

    @Test
    void constructor_rejects_url_with_query() {
        assertThrows(IllegalArgumentException.class,
                () -> new JndiDirectoryLookup(
                        "ldap://127.0.0.1:389/?scope=sub",
                        BIND_DN, BIND_PW, BASE_DN));
    }

    @Test
    void constructor_rejects_url_with_fragment() {
        assertThrows(IllegalArgumentException.class,
                () -> new JndiDirectoryLookup(
                        "ldap://127.0.0.1:389/#fragment",
                        BIND_DN, BIND_PW, BASE_DN));
    }

    @Test
    void constructor_rejects_url_without_host() {
        assertThrows(IllegalArgumentException.class,
                () -> new JndiDirectoryLookup("ldap:///dc=example,dc=com",
                        BIND_DN, BIND_PW, BASE_DN));
    }

    @Test
    void constructor_rejects_invalid_url_syntax() {
        assertThrows(IllegalArgumentException.class,
                () -> new JndiDirectoryLookup("ldap://[unclosed-bracket",
                        BIND_DN, BIND_PW, BASE_DN));
    }

    @Test
    void constructor_exception_message_does_not_echo_url() {
        try {
            new JndiDirectoryLookup(
                    "ldap://attacker:hunter2@127.0.0.1:389",
                    BIND_DN, BIND_PW, BASE_DN);
            fail("constructor should have thrown");
        } catch (IllegalArgumentException ex) {
            String msg = ex.getMessage() == null ? "" : ex.getMessage();
            assertFalse(msg.contains("hunter2"),
                    "exception must not include the secret password");
            assertFalse(msg.contains("attacker"),
                    "exception must not include the secret username");
        }
    }

    @Test
    void strict_loopback_only_accepts_127_0_0_0_through_127_255_255_255() {
        assertTrue(JndiDirectoryLookup.isLoopbackHost("127.0.0.1"));
        assertTrue(JndiDirectoryLookup.isLoopbackHost("127.255.255.255"));
        assertTrue(JndiDirectoryLookup.isLoopbackHost("127.0.0.0"));
        assertTrue(JndiDirectoryLookup.isLoopbackHost("localhost"));
        assertTrue(JndiDirectoryLookup.isLoopbackHost("::1"));
        assertFalse(JndiDirectoryLookup.isLoopbackHost("128.0.0.1"));
        assertFalse(JndiDirectoryLookup.isLoopbackHost("10.0.0.1"));
        assertFalse(JndiDirectoryLookup.isLoopbackHost("127.attacker.example"));
        assertFalse(JndiDirectoryLookup.isLoopbackHost("example.com"));
        assertFalse(JndiDirectoryLookup.isLoopbackHost(""));
        assertFalse(JndiDirectoryLookup.isLoopbackHost(null));
        assertFalse(JndiDirectoryLookup.isLoopbackHost("127.0.0"));
        assertFalse(JndiDirectoryLookup.isLoopbackHost("127.0.0.1.5"));
        assertFalse(JndiDirectoryLookup.isLoopbackHost("127.0.0.300"));
    }

    @Test
    void to_string_does_not_leak_url_binddn_or_password() throws Exception {
        JndiDirectoryLookup lookup = newLookup();
        try {
            String s = lookup.toString();
            assertFalse(s.contains(BIND_PW), "password must not appear");
            assertFalse(s.contains(BIND_DN), "bind DN must not appear");
            assertFalse(s.contains("127.0.0.1"),
                    "host/port must not appear");
        } finally {
            lookup.close();
        }
    }

    /** Documented limitation: NetBIOS domain is not inferred from the DN. */
    @Test
    void document_limitation_does_not_infer_netbios_domain_from_dn() throws Exception {
        // The lookup normalizes only within the configured BASE_DN. A
        // request for "EXAMPLE\alice" is correctly normalized to "alice"
        // and looked up under that configured tree only. There is no
        // automatic cross-tree correlation; that's a deployment decision.
        JndiDirectoryLookup lookup = newLookup();
        try {
            Optional<DirectoryUser> alice = lookup.find("EXAMPLE" + "\\" + "alice");
            assertTrue(alice.isPresent(),
                    "input is normalized within the configured base DN");
        } finally {
            lookup.close();
        }
    }
}
