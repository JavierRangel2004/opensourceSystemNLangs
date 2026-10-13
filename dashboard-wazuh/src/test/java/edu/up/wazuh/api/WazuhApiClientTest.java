package edu.up.wazuh.api;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import edu.up.wazuh.model.Agent;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class WazuhApiClientTest {

    private HttpServer server;
    private URI baseUri;

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.start();
        baseUri = URI.create("http://127.0.0.1:" + server.getAddress().getPort());
    }

    @AfterEach
    void stop() {
        if (server != null) server.stop(0);
    }

    @Test
    void rejects_http_against_non_loopback() {
        URI ext = URI.create("http://example.com:55000");
        assertThrows(IllegalArgumentException.class,
                () -> new WazuhApiClient(ext, "u", "p"));
    }

    @Test
    void rejects_http_against_non_numeric_127_hostname() {
        // 127.attacker.example starts with 127. but is NOT a numeric IPv4
        // address. The strict loopback test must reject it.
        URI malicious = URI.create("http://127.attacker.example:55000");
        assertThrows(IllegalArgumentException.class,
                () -> new WazuhApiClient(malicious, "u", "p"));
    }

    @Test
    void allows_http_loopback() {
        // Just verifying the constructor doesn't throw.
        new WazuhApiClient(baseUri, "u", "p");
    }

    @Test
    void authenticates_with_basic_and_paginates_using_offset_limit() throws Exception {
        Map<String, AtomicInteger> calls = new ConcurrentHashMap<>();
        register("/security/user/authenticate", exchange -> {
            calls.computeIfAbsent("auth", k -> new AtomicInteger()).incrementAndGet();
            String auth = exchange.getRequestHeaders().getFirst("Authorization");
            assertNotNull(auth, "Authorization header must be sent");
            assertTrue(auth.startsWith("Basic "), "must use Basic auth");
            byte[] token = "\"test.jwt.token\"".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, token.length);
            exchange.getResponseBody().write(token);
            exchange.close();
        });
        registerPage(calls, /*total*/ 3, /*pageSize*/ 500);

        WazuhApiClient client = new WazuhApiClient(baseUri, "admin", "secret");
        List<Agent> all = client.fetchAgents();

        assertEquals(3, all.size());
        assertEquals("001", all.get(0).id());
        assertEquals("ACME-Linux-1", all.get(0).os(), "OS preserved");
        assertEquals(1, calls.get("auth").get(),
                "auth should happen once and the token be reused");
        assertEquals(1, calls.getOrDefault("agents", new AtomicInteger()).get(),
                "should fetch all 3 agents in one page");
    }

    @Test
    void returns_all_when_single_page_covers_total() throws Exception {
        Map<String, AtomicInteger> calls = new ConcurrentHashMap<>();
        register("/security/user/authenticate", exchange -> {
            calls.computeIfAbsent("auth", k -> new AtomicInteger()).incrementAndGet();
            byte[] token = "test.jwt.token".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, token.length);
            exchange.getResponseBody().write(token);
            exchange.close();
        });
        // Total 4 items, well under DEFAULT_LIMIT. The loop should stop after
        // one HTTP call because the affected_items size < limit.
        registerPage(calls, /*total*/ 4, /*pageSize*/ 500);

        WazuhApiClient client = new WazuhApiClient(baseUri, "admin", "secret");
        List<Agent> all = client.fetchAgents();
        assertEquals(4, all.size());
        assertEquals(1, calls.getOrDefault("agents", new AtomicInteger()).get(),
                "single page suffices when total <= DEFAULT_LIMIT");
    }

    @Test
    void walks_multiple_pages_when_first_page_returns_full() throws Exception {
        Map<String, AtomicInteger> calls = new ConcurrentHashMap<>();
        register("/security/user/authenticate", exchange -> {
            byte[] token = "test.jwt.token".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, token.length);
            exchange.getResponseBody().write(token);
            exchange.close();
        });
        // 1100 agents total to force three pages at DEFAULT_LIMIT=500.
        registerSlicedPage(calls, "/agents", 1100, 500);

        WazuhApiClient client = new WazuhApiClient(baseUri, "admin", "secret");
        List<Agent> all = client.fetchAgents();
        assertEquals(1100, all.size());
        int agentCalls = calls.getOrDefault("agents", new AtomicInteger()).get();
        assertEquals(3, agentCalls, "should fetch 3 pages of 500/500/100");
    }

    @Test
    void sends_authorization_bearer_header_with_token() throws Exception {
        register("/security/user/authenticate", exchange -> {
            byte[] token = "abc.def.ghi".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, token.length);
            exchange.getResponseBody().write(token);
            exchange.close();
        });
        Map<String, AtomicInteger> calls = new ConcurrentHashMap<>();
        register("/agents", exchange -> {
            String auth = exchange.getRequestHeaders().getFirst("Authorization");
            assertNotNull(auth);
            assertEquals("Bearer abc.def.ghi", auth);
            calls.computeIfAbsent("agents", k -> new AtomicInteger()).incrementAndGet();
            writeJson(exchange, 200, """
                    {"error": 0,
                     "data": {"total_affected_items": 1,
                              "affected_items": [
                                {"id": "1", "name": "n1", "status": "active",
                                 "ip": "10.0.0.1",
                                 "os": {"platform": "linux", "name": "Debian", "version": "12"}}
                              ]}}
                    """);
            return;
        });
        WazuhApiClient client = new WazuhApiClient(baseUri, "admin", "secret");
        List<Agent> all = client.fetchAgents();
        assertEquals(1, all.size());
        assertEquals("Debian 12", all.get(0).os());
    }

    @Test
    void renews_token_once_after_401() throws Exception {
        AtomicInteger authHits = new AtomicInteger();
        AtomicInteger agentHits = new AtomicInteger();
        register("/security/user/authenticate", exchange -> {
            int n = authHits.incrementAndGet();
            byte[] token = ("tok.abcd.renewed" + n).getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, token.length);
            exchange.getResponseBody().write(token);
            exchange.close();
        });
        register("/agents", exchange -> {
            int n = agentHits.incrementAndGet();
            if (n == 1) {
                writeJson(exchange, 401, "{\"error\":401}");
                return;
            }
            String auth = exchange.getRequestHeaders().getFirst("Authorization");
            assertEquals("Bearer tok.abcd.renewed2", auth,
                    "after re-auth the new token must be used");
            writeJson(exchange, 200, """
                    {"error": 0,
                     "data": {"total_affected_items": 1,
                              "affected_items": [
                                {"id": "1", "name": "n1", "status": "active",
                                 "ip": "10.0.0.1", "os": "Linux"}
                              ]}}
                    """);
        });
        WazuhApiClient client = new WazuhApiClient(baseUri, "admin", "secret");
        List<Agent> all = client.fetchAgents();
        assertEquals(1, all.size());
        assertEquals(2, authHits.get(), "should re-authenticate exactly once");
        assertEquals(2, agentHits.get(), "first call returns 401, retry succeeds");
    }

    @Test
    void surfaces_404_as_wazuh_exception_without_body() throws Exception {
        register("/security/user/authenticate", exchange -> {
            byte[] token = "tok.abcd.efgh".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, token.length);
            exchange.getResponseBody().write(token);
            exchange.close();
        });
        register("/agents", exchange -> writeJson(exchange, 404,
                "{\"error\":{\"message\":\"secret internal hint\"}}"));
        WazuhApiClient client = new WazuhApiClient(baseUri, "admin", "secret");
        WazuhApiException ex = assertThrows(WazuhApiException.class,
                client::fetchAgents);
        assertEquals(404, ex.statusCode());
        assertFalse(ex.getMessage().contains("secret"),
                "exception message must not include response body");
    }

    @Test
    void surfaces_5xx_as_manager_unavailable() throws Exception {
        register("/security/user/authenticate", exchange -> {
            byte[] token = "tok.abcd.efgh".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, token.length);
            exchange.getResponseBody().write(token);
            exchange.close();
        });
        register("/agents", exchange -> writeJson(exchange, 503, "{}"));
        WazuhApiClient client = new WazuhApiClient(baseUri, "admin", "secret");
        WazuhApiException ex = assertThrows(WazuhApiException.class,
                client::fetchAgents);
        assertEquals(503, ex.statusCode());
    }

    @Test
    void throws_when_envelope_error_is_non_zero() throws Exception {
        register("/security/user/authenticate", exchange -> {
            byte[] token = "tok.abcd.efgh".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, token.length);
            exchange.getResponseBody().write(token);
            exchange.close();
        });
        // 200 status but error:1 in the body — must still be treated as failure.
        register("/agents", exchange -> writeJson(exchange, 200, """
                {"error": 1, "message": "secret internal hint",
                 "data": {"total_affected_items": 0, "affected_items": []}}
                """));
        WazuhApiClient client = new WazuhApiClient(baseUri, "admin", "secret");
        WazuhApiException ex = assertThrows(WazuhApiException.class,
                client::fetchAgents);
        assertEquals(200, ex.statusCode());
        assertFalse(ex.getMessage().contains("secret"),
                "exception must not include the response message");
    }

    @Test
    void throws_when_failed_items_present() throws Exception {
        register("/security/user/authenticate", exchange -> {
            byte[] token = "tok.abcd.efgh".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, token.length);
            exchange.getResponseBody().write(token);
            exchange.close();
        });
        register("/agents", exchange -> writeJson(exchange, 200, """
                {"error": 0,
                 "data": {"total_affected_items": 0, "affected_items": [],
                          "failed_items": [{"error": {"code": 1004,
                                                       "message": "secret detail"}}]}}
                """));
        WazuhApiClient client = new WazuhApiClient(baseUri, "admin", "secret");
        WazuhApiException ex = assertThrows(WazuhApiException.class,
                client::fetchAgents);
        assertFalse(ex.getMessage().contains("secret"));
    }

    @Test
    void throws_on_incomplete_pagination_when_total_exceeds_returned() throws Exception {
        // Server reports total_affected_items=10 but only ever returns short
        // pages of two, never enough to reach total.
        Map<String, AtomicInteger> calls = new ConcurrentHashMap<>();
        register("/security/user/authenticate", exchange -> {
            byte[] token = "tok.abcd.efgh".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, token.length);
            exchange.getResponseBody().write(token);
            exchange.close();
        });
        register("/agents", exchange -> {
            calls.computeIfAbsent("agents", k -> new AtomicInteger()).incrementAndGet();
            String json = """
                    {"error": 0,
                     "data": {"total_affected_items": 10,
                              "affected_items": [
                                {"id": "1", "name": "n1", "status": "active",
                                 "ip": "10.0.0.1", "os": "Linux"},
                                {"id": "2", "name": "n2", "status": "active",
                                 "ip": "10.0.0.2", "os": "Linux"}
                              ]}}
                    """;
            writeJson(exchange, 200, json);
        });
        WazuhApiClient client = new WazuhApiClient(baseUri, "admin", "secret");
        assertThrows(WazuhApiException.class, client::fetchAgents);
    }

    @Test
    void to_string_does_not_leak_username_uri_password_or_token() {
        WazuhApiClient client = new WazuhApiClient(baseUri, "admin", "secret");
        String s = client.toString();
        assertFalse(s.contains("secret"), "password must not appear");
        assertFalse(s.contains("admin"), "privileged username must not appear");
        assertFalse(s.contains("127.0.0.1"), "host must not appear");
        assertFalse(s.contains("Bearer"), "no token leakage");
        // The implementation may still identify the type; it must remain secret-free.
        assertTrue(s.contains("WazuhApiClient"));
    }

    @Test
    void empty_agent_list_is_returned_as_empty_immutable_list() throws Exception {
        register("/security/user/authenticate", exchange -> {
            byte[] token = "tok.abcd.efgh".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, token.length);
            exchange.getResponseBody().write(token);
            exchange.close();
        });
        register("/agents", exchange -> writeJson(exchange, 200, """
                {"error": 0,
                 "data": {"total_affected_items": 0, "affected_items": []}}
                """));
        WazuhApiClient client = new WazuhApiClient(baseUri, "admin", "secret");
        List<Agent> agents = client.fetchAgents();
        assertEquals(0, agents.size());
        assertThrows(UnsupportedOperationException.class, () -> agents.add(null));
    }

    @Test
    void pagination_url_includes_offset_and_limit_query_params() throws Exception {
        register("/security/user/authenticate", exchange -> {
            byte[] token = "tok.abcd.efgh".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, token.length);
            exchange.getResponseBody().write(token);
            exchange.close();
        });
        List<String> queries = new ArrayList<>();
        register("/agents", exchange -> {
            String q = exchange.getRequestURI().getRawQuery();
            queries.add(q == null ? "" : q);
            writeJson(exchange, 200, """
                    {"error": 0,
                     "data": {"total_affected_items": 0, "affected_items": []}}
                    """);
        });
        // Run fetchAgentPage directly to test individual offsets/limits.
        WazuhApiClient client = new WazuhApiClient(baseUri, "admin", "secret");
        client.fetchAgentPage(0, 250);
        client.fetchAgentPage(750, 250);
        assertEquals("offset=0&limit=250", queries.get(0));
        assertEquals("offset=750&limit=250", queries.get(1));
    }

    @Test
    void rejects_malformed_empty_envelope() throws Exception {
        register("/security/user/authenticate", exchange -> {
            byte[] token = "tok.abcd.efgh".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, token.length);
            exchange.getResponseBody().write(token);
            exchange.close();
        });
        // 200 status, but body is just {} — must be rejected, not treated
        // as an empty inventory.
        register("/agents", exchange -> writeJson(exchange, 200, "{}"));
        WazuhApiClient client = new WazuhApiClient(baseUri, "admin", "secret");
        WazuhApiException ex = assertThrows(WazuhApiException.class,
                client::fetchAgents);
        assertTrue(ex.getMessage().contains("invalid envelope"),
                "ex must signal envelope problem");
    }

    @Test
    void rejects_envelope_without_total_affected_items() throws Exception {
        register("/security/user/authenticate", exchange -> {
            byte[] token = "tok.abcd.efgh".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, token.length);
            exchange.getResponseBody().write(token);
            exchange.close();
        });
        register("/agents", exchange -> writeJson(exchange, 200, """
                {"error": 0, "data": {"affected_items": []}}
                """));
        WazuhApiClient client = new WazuhApiClient(baseUri, "admin", "secret");
        WazuhApiException ex = assertThrows(WazuhApiException.class,
                client::fetchAgents);
        assertTrue(ex.getMessage().contains("invalid envelope"));
    }

    @Test
    void rejects_envelope_with_negative_total() throws Exception {
        register("/security/user/authenticate", exchange -> {
            byte[] token = "tok.abcd.efgh".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, token.length);
            exchange.getResponseBody().write(token);
            exchange.close();
        });
        register("/agents", exchange -> writeJson(exchange, 200, """
                {"error": 0, "data": {"total_affected_items": -1, "affected_items": []}}
                """));
        WazuhApiClient client = new WazuhApiClient(baseUri, "admin", "secret");
        WazuhApiException ex = assertThrows(WazuhApiException.class,
                client::fetchAgents);
        assertTrue(ex.getMessage().contains("invalid envelope"));
    }

    @Test
    void fails_when_failed_items_lives_under_data_in_real_shape() throws Exception {
        // Real Wazuh envelope puts failed_items under data, not at the root.
        // Using the authentic shape the manager actually returns must also
        // trigger the failure path.
        register("/security/user/authenticate", exchange -> {
            byte[] token = "tok.abcd.efgh".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, token.length);
            exchange.getResponseBody().write(token);
            exchange.close();
        });
        register("/agents", exchange -> writeJson(exchange, 200, """
                {"error": 1,
                 "data": {"total_affected_items": 0, "total_failed_items": 1,
                          "failed_items": [{"error": {"code": 1004,
                                                      "message": "secret"}}],
                          "affected_items": []}}
                """));
        WazuhApiClient client = new WazuhApiClient(baseUri, "admin", "secret");
        WazuhApiException ex = assertThrows(WazuhApiException.class,
                client::fetchAgents);
        assertFalse(ex.getMessage().contains("secret"),
                "exception must not include the failed item message");
    }

    @Test
    void rejects_token_with_multiline_content() throws Exception {
        register("/security/user/authenticate", exchange -> {
            // A multi-line response body (CR/LF embedded) must not be cached
            // as a token. The header validator would throw and echo the body.
            byte[] token = "line1\nline2\rline3".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, token.length);
            exchange.getResponseBody().write(token);
            exchange.close();
        });
        WazuhApiClient client = new WazuhApiClient(baseUri, "admin", "secret");
        WazuhApiException ex = assertThrows(WazuhApiException.class,
                () -> client.fetchAgents());
        assertTrue(ex.getMessage().contains("invalid token"),
                "ex must signal invalid token");
        // No Bearer ... must be reconstructed from the body, regardless of
        // what was returned.
        assertFalse(ex.getMessage().contains("line1"),
                "ex message must not echo the response body");
    }

    @Test
    void rejects_token_missing_segments() throws Exception {
        register("/security/user/authenticate", exchange -> {
            byte[] token = "not-a-jwt".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, token.length);
            exchange.getResponseBody().write(token);
            exchange.close();
        });
        WazuhApiClient client = new WazuhApiClient(baseUri, "admin", "secret");
        WazuhApiException ex = assertThrows(WazuhApiException.class,
                () -> client.fetchAgents());
        assertTrue(ex.getMessage().contains("invalid token"));
    }

    @Test
    void allows_http_when_host_is_ipv6_bracketed_loopback() throws Exception {
        // URI.getHost() returns "[::1]" for http://[::1]:port; the strict
        // loopback check must strip the brackets and accept it.
        URI v6Loopback = URI.create("http://[::1]:" + server.getAddress().getPort());
        // Just verifying the constructor doesn't throw. Calls against this
        // URI would race with the shared test server, so we don't fetch.
        new WazuhApiClient(v6Loopback, "u", "p");
    }

    @Test
    void strips_brackets_from_ipv6_loopback() {
        assertEquals("::1", WazuhApiClient.stripBrackets("[::1]"));
        assertEquals("0:0:0:0:0:0:0:1",
                WazuhApiClient.stripBrackets("[0:0:0:0:0:0:0:1]"));
        assertEquals("example.com", WazuhApiClient.stripBrackets("example.com"));
        assertNull(WazuhApiClient.stripBrackets(null));
    }

    @Test
    void accepts_jwt_shaped_tokens_with_three_segments() {
        assertTrue(WazuhApiClient.isJwtShape(
                "abcd1234.efgh5678.ijkl9012"));
        // 3 base64url segments with padding accepted defensively.
        assertTrue(WazuhApiClient.isJwtShape(
                "AAAA.BBBB.===="));
        assertFalse(WazuhApiClient.isJwtShape(""));
        assertFalse(WazuhApiClient.isJwtShape("abc"));
        assertFalse(WazuhApiClient.isJwtShape("abc.def"));
        assertFalse(WazuhApiClient.isJwtShape("a.b.c.d"));
        assertFalse(WazuhApiClient.isJwtShape("a.b."));
        assertFalse(WazuhApiClient.isJwtShape(".b.c"));
        assertFalse(WazuhApiClient.isJwtShape("abc.def!\nghi"));
        assertFalse(WazuhApiClient.isJwtShape("has space.in.token"));
    }

    @Test
    void normalize_base_appends_trailing_slash() {
        URI without = URI.create("https://host/wazuh-api");
        URI normalized = WazuhApiClient.normalizeBase(without);
        assertTrue(normalized.toString().endsWith("/"),
                "base URI must end with / to enable relative resolution");
    }

    @Test
    void requests_resolve_relative_against_prefix() throws Exception {
        // Configure an HttpServer rooted at /wazuh-api-base/ and verify
        // that the agent request lands at /wazuh-api-base/agents, not
        // /agents.
        HttpServer prefixServer = HttpServer.create(
                new InetSocketAddress("127.0.0.1", 0), 0);
        try {
            java.util.List<String> authPath = new ArrayList<>();
            java.util.List<String> agentPath = new ArrayList<>();
            prefixServer.createContext("/wazuh-api-base/security/user/authenticate",
                    exchange -> {
                        authPath.add(exchange.getRequestURI().getPath());
                        byte[] token = "tok.abcd.efgh".getBytes(
                                StandardCharsets.UTF_8);
                        exchange.sendResponseHeaders(200, token.length);
                        exchange.getResponseBody().write(token);
                        exchange.close();
                    });
            prefixServer.createContext("/wazuh-api-base/agents", exchange -> {
                agentPath.add(exchange.getRequestURI().getPath());
                writeJson(exchange, 200, """
                        {"error": 0,
                         "data": {"total_affected_items": 0, "affected_items": []}}
                        """);
            });
            prefixServer.start();
            URI base = URI.create("http://127.0.0.1:"
                    + prefixServer.getAddress().getPort() + "/wazuh-api-base");
            WazuhApiClient client = new WazuhApiClient(base, "admin", "secret");
            client.fetchAgents();
            assertEquals("/wazuh-api-base/security/user/authenticate", authPath.get(0));
            assertEquals("/wazuh-api-base/agents", agentPath.get(0));
        } finally {
            prefixServer.stop(0);
        }
    }

    // ----------------------- helpers -----------------------

    private void register(String path, HttpHandler handler) {
        server.createContext(path, handler);
    }

    /**
     * Registers a sliced /agents endpoint: returns only the slice described
     * by the {@code offset} and {@code limit} request parameters and reports
     * the total agent count once. Increments {@code calls("agents")} for each
     * request so the caller can verify how many pages were walked.
     */
    private void registerSlicedPage(Map<String, AtomicInteger> calls, String path,
                                    int total, int pageSize) {
        register(path, exchange -> {
            calls.computeIfAbsent("agents", k -> new AtomicInteger()).incrementAndGet();
            String query = exchange.getRequestURI().getRawQuery();
            int offset = 0;
            int limit = pageSize;
            if (query != null) {
                for (String kv : query.split("&")) {
                    String[] parts = kv.split("=", 2);
                    if (parts.length == 2) {
                        if ("offset".equals(parts[0])) offset = Integer.parseInt(parts[1]);
                        else if ("limit".equals(parts[0])) limit = Integer.parseInt(parts[1]);
                    }
                }
            }
            int end = Math.min(offset + limit, total);
            StringBuilder sb = new StringBuilder();
            sb.append("{\"error\":0,\"data\":{\"total_affected_items\":")
              .append(total)
              .append(",\"affected_items\":[");
            for (int i = offset; i < end; i++) {
                if (i > offset) sb.append(",");
                sb.append("{\"id\":\"").append(String.format("%04d", i))
                  .append("\",\"name\":\"agent-").append(i)
                  .append("\",\"status\":\"active\",")
                  .append("\"ip\":\"10.")
                  .append(i / 100000 % 256).append('.')
                  .append(i / 1000 % 256).append('.')
                  .append(i % 256)
                  .append("\",\"os\":\"Linux\"}");
            }
            sb.append("]}}");
            writeJson(exchange, 200, sb.toString());
        });
    }

    private interface BodyHandler {
        void handle(HttpExchange exchange) throws IOException;
    }

    private void registerPage(Map<String, AtomicInteger> calls, int total, int pageSize) throws IOException {
        List<Map<String, Object>> items = new ArrayList<>();
        for (int i = 1; i <= total; i++) {
            Map<String, Object> item = new HashMap<>();
            item.put("id", String.format("%03d", i));
            item.put("name", "agent-" + i);
            item.put("status", "active");
            item.put("ip", "10.0.0." + i);
            item.put("os", "ACME-Linux-1");
            items.add(item);
        }
        register("/agents", exchange -> {
            calls.computeIfAbsent("agents", k -> new AtomicInteger()).incrementAndGet();
            String query = exchange.getRequestURI().getRawQuery();
            int offset = 0;
            int limit = pageSize;
            if (query != null) {
                for (String kv : query.split("&")) {
                    String[] parts = kv.split("=", 2);
                    if (parts.length == 2) {
                        if ("offset".equals(parts[0])) offset = Integer.parseInt(parts[1]);
                        else if ("limit".equals(parts[0])) limit = Integer.parseInt(parts[1]);
                    }
                }
            }
            int end = Math.min(offset + limit, items.size());
            StringBuilder sb = new StringBuilder();
            sb.append("{\"error\":0,\"data\":{\"total_affected_items\":")
              .append(items.size())
              .append(",\"affected_items\":[");
            for (int i = offset; i < end; i++) {
                Map<String, Object> a = items.get(i);
                if (i > offset) sb.append(",");
                sb.append("{\"id\":\"").append(a.get("id")).append("\",")
                  .append("\"name\":\"").append(a.get("name")).append("\",")
                  .append("\"status\":\"").append(a.get("status")).append("\",")
                  .append("\"ip\":\"").append(a.get("ip")).append("\",")
                  .append("\"os\":\"").append(a.get("os")).append("\"}");
            }
            sb.append("]}}");
            writeJson(exchange, 200, sb.toString());
        });
    }

    private static void writeJson(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }
}
