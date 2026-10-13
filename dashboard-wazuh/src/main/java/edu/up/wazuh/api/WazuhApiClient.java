package edu.up.wazuh.api;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSyntaxException;
import edu.up.wazuh.model.Agent;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;

/**
 * Minimal Wazuh manager API client. Authenticates with
 * {@code POST /security/user/authenticate?raw=true} using HTTP Basic
 * credentials, caches the JWT in memory and refreshes it at most once on
 * {@code 401}. HTTPS uses the JDK's validating SSL context. Plain HTTP is
 * only accepted against a strict loopback address (used for unit tests).
 *
 * <p>Endpoints are resolved relative to the configured base URI's path so a
 * deployment behind a prefix (e.g. {@code https://host/wazuh-api}) still
 * receives requests at the prefix.
 *
 * <p>The class deliberately avoids exposing the password or the JWT in
 * {@link #toString()} or in {@link WazuhApiException} messages. The base
 * URI and the bind username — both potentially fingerprintable — are also
 * omitted from {@link #toString()}.
 */
public class WazuhApiClient {

    static final int DEFAULT_LIMIT = 500;
    /** Hard safety cap; pagination that exceeds this raises an explicit error. */
    static final int MAX_OFFSET = 100_000;
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(20);

    private final URI baseUri;
    private final String username;
    private final char[] password;
    private final HttpClient http;
    private final Object tokenLock = new Object();
    private volatile String cachedToken;

    public WazuhApiClient(URI baseUri, String username, String password) {
        Objects.requireNonNull(baseUri, "baseUri");
        Objects.requireNonNull(username, "username");
        this.baseUri = normalizeBase(baseUri);
        this.username = username;
        this.password = password == null ? new char[0] : password.toCharArray();
        String scheme = this.baseUri.getScheme();
        if (!"https".equalsIgnoreCase(scheme) && !"http".equalsIgnoreCase(scheme)) {
            throw new IllegalArgumentException("unsupported Wazuh scheme");
        }
        if ("http".equalsIgnoreCase(scheme) && !isLoopback(this.baseUri)) {
            throw new IllegalArgumentException(
                    "plain http only allowed for loopback addresses");
        }
        this.http = HttpClient.newBuilder()
                .connectTimeout(CONNECT_TIMEOUT)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    /**
     * Ensures the URI's path ends with a single {@code /}. RFC 3986
     * resolution drops the base path when the reference is absolute
     * (e.g. {@code /agents}), so making the prefix an empty segment turns
     * the absolute reference into a relative one. Without this, a manager
     * at {@code https://host/wazuh-api/} would receive requests at
     * {@code https://host/agents}, sending Basic credentials to the wrong
     * origin.
     */
    static URI normalizeBase(URI base) {
        String path = base.getPath();
        if (path == null || path.isEmpty()) {
            try {
                return new URI(base.getScheme(), base.getUserInfo(),
                        base.getHost(), base.getPort(), "/", null, null);
            } catch (URISyntaxException e) {
                throw new IllegalArgumentException("invalid base URI", e);
            }
        }
        if (path.endsWith("/")) return base;
        try {
            return new URI(base.getScheme(), base.getUserInfo(),
                    base.getHost(), base.getPort(), path + "/", null, null);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("invalid base URI", e);
        }
    }

    /** Fetches all agents via internal pagination. Returns an immutable list. */
    public List<Agent> fetchAgents() throws IOException, InterruptedException {
        List<Agent> result = new ArrayList<>();
        int offset = 0;
        int total = -1;
        while (true) {
            Page page = fetchAgentPage(offset, DEFAULT_LIMIT);
            int pageSize = page.agents().size();
            result.addAll(page.agents());
            total = page.total();
            boolean atOrPastTotal = total >= 0 && result.size() >= total;
            if (pageSize == 0) {
                if (total >= 0 && result.size() < total) {
                    throw new WazuhApiException(200,
                            "incomplete pagination: empty page before total");
                }
                break;
            }
            if (pageSize < DEFAULT_LIMIT) {
                if (total >= 0 && result.size() < total) {
                    throw new WazuhApiException(200,
                            "incomplete pagination: short page before total");
                }
                break;
            }
            if (atOrPastTotal) {
                break;
            }
            offset += pageSize;
            if (offset > MAX_OFFSET) {
                throw new WazuhApiException(200,
                        "pagination exceeded safety cap");
            }
        }
        return List.copyOf(result);
    }

    /** Returns a single page of agents using Wazuh's offset/limit pagination. */
    Page fetchAgentPage(int offset, int limit) throws IOException, InterruptedException {
        if (offset < 0 || limit <= 0) {
            throw new IllegalArgumentException("invalid pagination arguments");
        }
        // Relative resolution so the prefix stored on baseUri is preserved.
        URI endpoint = baseUri.resolve(
                "agents?offset=" + offset + "&limit=" + limit);
        HttpResponse<String> resp = sendWithAuth(token ->
                HttpRequest.newBuilder(endpoint)
                        .timeout(REQUEST_TIMEOUT)
                        .header("Authorization", "Bearer " + token)
                        .header("Accept", "application/json")
                        .GET()
                        .build());
        if (resp.statusCode() / 100 != 2) {
            throw new WazuhApiException(resp.statusCode(), "manager error");
        }
        JsonObject body;
        try {
            body = JsonParser.parseString(resp.body()).getAsJsonObject();
        } catch (JsonSyntaxException | IllegalStateException e) {
            throw new WazuhApiException(resp.statusCode(), "invalid response body");
        }
        JsonObject data = requireDataObject(body, resp.statusCode());
        int total = requireNonNegativeInt(data, "total_affected_items", resp.statusCode());
        JsonArray items = data.has("affected_items")
                && data.get("affected_items").isJsonArray()
                ? data.getAsJsonArray("affected_items") : new JsonArray();
        validateFailedItems(data, resp.statusCode());
        int err = readTopLevelError(body);
        if (err != 0) {
            throw new WazuhApiException(resp.statusCode(), "manager error");
        }
        List<Agent> agents = new ArrayList<>(items.size());
        for (JsonElement el : items) {
            if (!el.isJsonObject()) continue;
            agents.add(toAgent(el.getAsJsonObject()));
        }
        return new Page(List.copyOf(agents), total);
    }

    private static int readTopLevelError(JsonObject body) {
        if (!body.has("error") || body.get("error").isJsonNull()) return 0;
        JsonElement el = body.get("error");
        if (!el.isJsonPrimitive()) return 0;
        try {
            return el.getAsInt();
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private static JsonObject requireDataObject(JsonObject body, int httpStatus) throws WazuhApiException {
        if (!body.has("data") || body.get("data").isJsonNull()
                || !body.get("data").isJsonObject()) {
            throw new WazuhApiException(httpStatus, "invalid envelope");
        }
        return body.getAsJsonObject("data");
    }

    private static int requireNonNegativeInt(JsonObject data, String field, int httpStatus) throws WazuhApiException {
        if (!data.has(field) || data.get(field).isJsonNull()
                || !data.get(field).isJsonPrimitive()) {
            throw new WazuhApiException(httpStatus, "invalid envelope");
        }
        JsonPrimitive p = data.get(field).getAsJsonPrimitive();
        try {
            int v = p.getAsInt();
            if (v < 0) throw new WazuhApiException(httpStatus, "invalid envelope");
            return v;
        } catch (NumberFormatException e) {
            throw new WazuhApiException(httpStatus, "invalid envelope");
        }
    }

    private static void validateFailedItems(JsonObject data, int httpStatus) throws WazuhApiException {
        if (data.has("failed_items") && !data.get("failed_items").isJsonNull()) {
            if (!data.get("failed_items").isJsonArray()) {
                throw new WazuhApiException(httpStatus, "invalid envelope");
            }
            if (data.getAsJsonArray("failed_items").size() > 0) {
                throw new WazuhApiException(httpStatus, "manager error");
            }
        }
        if (data.has("total_failed_items") && !data.get("total_failed_items").isJsonNull()) {
            int totalFailed;
            try {
                totalFailed = data.get("total_failed_items").getAsInt();
            } catch (NumberFormatException e) {
                throw new WazuhApiException(httpStatus, "invalid envelope");
            }
            if (totalFailed > 0) {
                throw new WazuhApiException(httpStatus, "manager error");
            }
        }
    }

    private Agent toAgent(JsonObject obj) {
        String id = stringOrEmpty(obj, "id");
        String name = stringOrEmpty(obj, "name");
        String status = stringOrEmpty(obj, "status");
        String ip = stringOrEmpty(obj, "ip");
        String os;
        if (obj.has("os") && obj.get("os").isJsonObject()) {
            os = compactOs(obj.getAsJsonObject("os"));
        } else {
            os = stringOrEmpty(obj, "os");
        }
        return new Agent(id, name, status, ip, os);
    }

    private static String compactOs(JsonObject os) {
        String platform = stringOrEmpty(os, "platform");
        String name = stringOrEmpty(os, "name");
        String version = stringOrEmpty(os, "version");
        if (platform.isEmpty() && name.isEmpty() && version.isEmpty()) {
            return "";
        }
        if (name.isEmpty()) name = platform;
        if (version.isEmpty()) return name;
        return name + " " + version;
    }

    private static String stringOrEmpty(JsonObject obj, String field) {
        if (obj == null || !obj.has(field) || obj.get(field).isJsonNull()) return "";
        JsonElement el = obj.get(field);
        if (el.isJsonPrimitive()) return el.getAsString();
        return el.toString();
    }

    private HttpResponse<String> sendWithAuth(RequestBuilder builder) throws IOException, InterruptedException {
        String token = ensureToken();
        HttpResponse<String> resp = doSend(builder, token);
        if (resp.statusCode() != 401) {
            return handleNonAuth(resp);
        }
        synchronized (tokenLock) {
            cachedToken = null;
            token = ensureToken();
        }
        HttpResponse<String> retry = doSend(builder, token);
        return handleNonAuth(retry);
    }

    private static HttpResponse<String> handleNonAuth(HttpResponse<String> resp) throws WazuhApiException {
        int status = resp.statusCode();
        if (status / 100 == 2) return resp;
        if (status == 401) throw new WazuhApiException(401, "authentication failed");
        if (status == 404) throw new WazuhApiException(404, "endpoint not found");
        if (status >= 500) throw new WazuhApiException(status, "manager unavailable");
        throw new WazuhApiException(status, "request rejected");
    }

    private HttpResponse<String> doSend(RequestBuilder builder, String token) throws IOException, InterruptedException {
        HttpRequest req = builder.build(token);
        return http.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    private String ensureToken() throws IOException, InterruptedException {
        String local = cachedToken;
        if (local != null && !local.isEmpty()) return local;
        synchronized (tokenLock) {
            if (cachedToken != null && !cachedToken.isEmpty()) return cachedToken;
            cachedToken = authenticate();
            return cachedToken;
        }
    }

    String authenticate() throws IOException, InterruptedException {
        URI endpoint = baseUri.resolve("security/user/authenticate?raw=true");
        String basic = basicAuth(username, password);
        HttpRequest req = HttpRequest.newBuilder(endpoint)
                .timeout(REQUEST_TIMEOUT)
                .header("Authorization", basic)
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();
        HttpResponse<String> resp = http.send(req,
                HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (resp.statusCode() == 200) {
            String token = resp.body() == null ? "" : resp.body().trim();
            if (token.startsWith("\"") && token.endsWith("\"")) {
                token = token.substring(1, token.length() - 1);
            }
            if (!isJwtShape(token)) {
                // Refuse to cache or propagate a value that the header
                // builder would reject (and whose message would echo the
                // response body).
                throw new WazuhApiException(200, "invalid token");
            }
            return token;
        }
        if (resp.statusCode() == 401) {
            throw new WazuhApiException(401, "authentication failed");
        }
        throw new WazuhApiException(resp.statusCode(), "authentication rejected");
    }

    /**
     * Returns true only for a value shaped like a JWT: three non-empty
     * segments of base64url characters separated by dots, with no
     * whitespace, CR/LF, or control characters. The signature is not
     * verified — that's the manager's job — but malformed tokens are
     * rejected before the header builder would throw a JDK
     * IllegalArgumentException that echoes the offending value.
     */
    static boolean isJwtShape(String token) {
        if (token == null || token.isEmpty()) return false;
        for (int i = 0; i < token.length(); i++) {
            char c = token.charAt(i);
            // base64url: A-Z, a-z, 0-9, '-', '_'. base64url padded variants
            // ('=') are accepted defensively.
            if (c == '=') continue;
            boolean ok = (c >= 'A' && c <= 'Z')
                    || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9')
                    || c == '-' || c == '_' || c == '.';
            if (!ok) return false;
        }
        int dot1 = token.indexOf('.');
        if (dot1 <= 0) return false;
        int dot2 = token.indexOf('.', dot1 + 1);
        if (dot2 <= dot1 + 1) return false;
        if (dot2 != token.lastIndexOf('.')) return false;
        if (dot2 == token.length() - 1) return false;
        String tail = token.substring(dot2 + 1);
        if (tail.isEmpty()) return false;
        return true;
    }

    private static String basicAuth(String user, char[] pw) {
        StringBuilder sb = new StringBuilder();
        sb.append(user).append(':');
        sb.append(pw);
        String token = sb.toString();
        return "Basic " + Base64.getEncoder().encodeToString(
                token.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Strict loopback detection that never performs DNS lookups. Accepts
     * the literal {@code localhost}, the IPv6 loopback {@code ::1} (and
     * its canonical form), or a syntactically valid IPv4 address in the
     * {@code 127.0.0.0/8} block. Hostnames that merely start with
     * {@code 127.} but are not numeric (e.g. {@code 127.attacker.example})
     * are rejected.
     */
    static boolean isLoopback(URI uri) {
        return isLoopbackHost(stripBrackets(uri.getHost()));
    }

    /**
     * {@link URI#getHost()} keeps the surrounding brackets on IPv6
     * literals (e.g. {@code [::1]}); strip them before any host-text
     * comparison.
     */
    static String stripBrackets(String host) {
        if (host == null) return null;
        if (host.length() >= 2 && host.charAt(0) == '['
                && host.charAt(host.length() - 1) == ']') {
            return host.substring(1, host.length() - 1);
        }
        return host;
    }

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
    public String toString() {
        return "WazuhApiClient{id=" + System.identityHashCode(this) + "}";
    }

    /** Internal value type representing a single agent page. */
    public record Page(List<Agent> agents, int total) {}

    @FunctionalInterface
    interface RequestBuilder {
        HttpRequest build(String token);
    }
}
