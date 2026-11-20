package conformance;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockserver.client.MockServerClient;
import org.mockserver.matchers.MatchType;
import org.mockserver.matchers.Times;
import org.mockserver.mock.Expectation;
import org.mockserver.model.Cookie;
import org.mockserver.model.Delay;
import org.mockserver.model.HttpRequest;

import org.mockserver.model.JsonBody;
import org.mockserver.model.Parameter;
import org.mockserver.verify.VerificationTimes;
import org.testcontainers.mockserver.MockServerContainer;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockserver.model.HttpError.error;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;
import static org.mockserver.model.JsonBody.json;

/**
 * Everything M1 promises, written the way a Java integration test uses MockServer: a remote
 * {@link MockServerClient} against a container started by Testcontainers' MockServer module.
 * Subclasses pick the image; the assertions are identical for both.
 */
abstract class MockingSuite {

    static MockServerContainer container;
    static MockServerClient client;
    static final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    static void start(MockServerContainer c) {
        container = c;
        container.start();
        client = new MockServerClient(container.getHost(), container.getServerPort());
    }

    @AfterAll
    static void stop() {
        if (client != null) client.close();
        if (container != null) container.stop();
    }

    @BeforeEach
    void reset() {
        client.reset();
    }

    static HttpResponse<String> send(String method, String path, String body, String... headers) throws Exception {
        var builder = java.net.http.HttpRequest.newBuilder(URI.create(container.getEndpoint() + path))
            .timeout(Duration.ofSeconds(10))
            .method(method, body == null ? BodyPublishers.noBody() : BodyPublishers.ofString(body));
        for (int i = 0; i < headers.length; i += 2) builder.header(headers[i], headers[i + 1]);
        return http.send(builder.build(), BodyHandlers.ofString());
    }

    static HttpResponse<String> get(String path, String... headers) throws Exception {
        return send("GET", path, null, headers);
    }

    @Test
    void clientSeesServerAsRunning() {
        assertTrue(client.hasStarted());
        assertTrue(client.isRunning());
    }

    @Test
    void respondsWithStatusHeadersAndBody() throws Exception {
        client.when(request().withMethod("GET").withPath("/hello"))
            .respond(response().withStatusCode(201).withHeader("X-Out", "1").withBody("hi"));
        var r = get("/hello");
        assertEquals(201, r.statusCode());
        assertEquals("1", r.headers().firstValue("X-Out").orElseThrow());
        assertEquals("hi", r.body());
    }

    @Test
    void jsonResponseBodyGetsJsonContentType() throws Exception {
        client.when(request().withPath("/json")).respond(response().withBody(json("{\"a\": [1, 2]}")));
        var r = get("/json");
        assertEquals(200, r.statusCode());
        assertTrue(r.headers().firstValue("Content-Type").orElseThrow().startsWith("application/json"));
        // The client sends the JSON as an object; MockServer answers it pretty-printed.
        assertEquals("{\n  \"a\" : [ 1, 2 ]\n}", r.body());
    }

    @Test
    void matchesHeadersQueryAndCookies() throws Exception {
        client.when(request().withPath("/q")
                .withHeader("X-Api-Key", "secret")
                .withQueryStringParameter("page", "[0-9]+")
                .withCookie("sid", "abc"))
            .respond(response().withBody("matched"));
        assertEquals("matched", get("/q?page=12&other=x", "X-Api-Key", "secret", "Cookie", "sid=abc").body());
        assertEquals(404, get("/q?page=12", "X-Api-Key", "secret", "Host", "localhost:1080").statusCode(), "cookie missing");
        assertEquals(404, get("/q?page=x", "X-Api-Key", "secret", "Cookie", "sid=abc", "Host", "localhost:1080").statusCode());
    }

    @Test
    void matchesJsonBodyOnlyMatchingFields() throws Exception {
        client.when(request().withMethod("POST").withPath("/orders")
                .withBody(json("{\"customer\": {\"id\": 7}, \"items\": [1]}", MatchType.ONLY_MATCHING_FIELDS)))
            .respond(response().withStatusCode(202));
        assertEquals(202, send("POST", "/orders", "{\"items\":[2,1],\"customer\":{\"id\":7,\"name\":\"x\"}}",
            "Content-Type", "application/json").statusCode());
        assertEquals(404, send("POST", "/orders", "{\"items\":[1],\"customer\":{\"id\":8}}",
            "Content-Type", "application/json", "Host", "localhost:1080").statusCode());
    }

    @Test
    void matchesJsonBodyStrictly() throws Exception {
        client.when(request().withPath("/strict").withBody(json("{\"a\": 1}", MatchType.STRICT)))
            .respond(response().withBody("strict"));
        assertEquals("strict", send("POST", "/strict", "{\"a\":1}").body());
        assertEquals(404, send("POST", "/strict", "{\"a\":1,\"b\":2}", "Host", "localhost:1080").statusCode());
    }

    @Test
    void pathTemplatesAndRegex() throws Exception {
        client.when(request().withPath("/users/{id}").withPathParameter("id", "[0-9]+"))
            .respond(response().withBody("user"));
        client.when(request().withPath("/files/.*\\.txt")).respond(response().withBody("file"));
        assertEquals("user", get("/users/42").body());
        assertEquals("file", get("/files/a/b.txt").body());
        assertEquals(404, get("/users/abc", "Host", "localhost:1080").statusCode());
    }

    @Test
    void timesAreConsumedThenFallThrough() throws Exception {
        client.when(request().withPath("/once"), Times.exactly(1)).respond(response().withBody("first"));
        client.when(request().withPath("/once")).respond(response().withBody("fallback"));
        assertEquals("first", get("/once").body());
        assertEquals("fallback", get("/once").body());
    }

    @Test
    void priorityWins() throws Exception {
        client.when(request().withPath("/p"), Times.unlimited(), org.mockserver.matchers.TimeToLive.unlimited(), 1)
            .respond(response().withBody("low"));
        client.when(request().withPath("/p"), Times.unlimited(), org.mockserver.matchers.TimeToLive.unlimited(), 10)
            .respond(response().withBody("high"));
        assertEquals("high", get("/p").body());
    }

    @Test
    void upsertByIdReplacesTheResponse() throws Exception {
        client.upsert(new Expectation(request().withPath("/u")).withId("fixed").thenRespond(response().withBody("v1")));
        client.upsert(new Expectation(request().withPath("/u")).withId("fixed").thenRespond(response().withBody("v2")));
        assertEquals("v2", get("/u").body());
        assertEquals(1, client.retrieveActiveExpectations(request().withPath("/u")).length);
    }

    @Test
    void createReturnsTheStoredExpectations() {
        Expectation[] created = client.when(request().withPath("/c")).respond(response().withBody("c"));
        assertEquals(1, created.length);
        assertNotNull(created[0].getId());
        assertEquals("/c", ((HttpRequest) created[0].getHttpRequest()).getPath().getValue());
    }

    @Test
    void delayIsApplied() throws Exception {
        client.when(request().withPath("/slow"))
            .respond(response().withBody("late").withDelay(new Delay(TimeUnit.MILLISECONDS, 300)));
        long start = System.nanoTime();
        assertEquals("late", get("/slow").body());
        assertTrue(Duration.ofNanos(System.nanoTime() - start).toMillis() >= 290);
    }

    @Test
    void errorDropsTheConnection() {
        client.when(request().withPath("/drop")).error(error().withDropConnection(true));
        assertThrows(IOException.class, () -> get("/drop"));
    }

    @Test
    void verifyPassesAndFails() throws Exception {
        client.when(request().withPath("/v")).respond(response().withBody("v"));
        get("/v");
        client.verify(request().withPath("/v"), VerificationTimes.exactly(1));
        client.verify(request().withPath("/v"), VerificationTimes.atLeast(1));
        client.verify(request().withPath("/never"), VerificationTimes.never());
        AssertionError e = assertThrows(AssertionError.class,
            () -> client.verify(request().withPath("/v"), VerificationTimes.exactly(2)));
        assertTrue(e.getMessage().startsWith("Request not found exactly 2 times, expected:<{"), e.getMessage());
    }

    @Test
    void verifySequence() throws Exception {
        get("/one");
        get("/two");
        client.verify(request().withPath("/one"), request().withPath("/two"));
        assertThrows(AssertionError.class, () -> client.verify(request().withPath("/two"), request().withPath("/one")));
    }

    @Test
    void retrieveRecordedRequests() throws Exception {
        get("/r1?x=1", "X-H", "h");
        send("POST", "/r2", "{\"k\":1}", "Content-Type", "application/json");
        HttpRequest[] all = client.retrieveRecordedRequests(null);
        assertEquals(2, all.length);
        assertEquals("/r1", all[0].getPath().getValue());
        assertEquals("h", all[0].getFirstHeader("X-H"));
        assertEquals("1", all[0].getFirstQueryStringParameter("x"));
        HttpRequest[] posts = client.retrieveRecordedRequests(request().withMethod("POST"));
        assertEquals(1, posts.length);
        assertEquals("{\n  \"k\" : 1\n}", posts[0].getBodyAsString());
    }

    @Test
    void retrieveRequestsAndResponses() throws Exception {
        client.when(request().withPath("/rr")).respond(response().withStatusCode(203).withBody("x"));
        get("/rr");
        org.mockserver.model.LogEventRequestAndResponse[] exchanges = client.retrieveRecordedRequestsAndResponses(request().withPath("/rr"));
        assertEquals(1, exchanges.length);
        assertEquals(203, exchanges[0].getHttpResponse().getStatusCode());
    }

    @Test
    void clearRemovesExpectationsAndLogs() throws Exception {
        client.when(request().withPath("/a")).respond(response().withBody("a"));
        client.when(request().withPath("/b")).respond(response().withBody("b"));
        get("/a");
        client.clear(request().withPath("/a"));
        assertEquals(1, client.retrieveActiveExpectations(null).length);
        assertEquals(0, client.retrieveRecordedRequests(request().withPath("/a")).length);
        assertEquals("b", get("/b").body());
    }

    @Test
    void unmatchedThroughMappedPortIs502LikeMockServer() throws Exception {
        // The Host header is the Testcontainers-mapped port, which is foreign inside the container.
        assertEquals(502, get("/nothing").statusCode());
    }

    @Test
    void unmatchedWithLocalHostIs404() throws Exception {
        assertEquals(404, get("/nothing", "Host", "localhost:1080").statusCode());
    }

    @Test
    void formParameters() throws Exception {
        client.when(request().withPath("/form").withBody(org.mockserver.model.ParameterBody.params(Parameter.param("name", "bob"))))
            .respond(response().withBody("form"));
        assertEquals("form", send("POST", "/form", "name=bob&x=1", "Content-Type", "application/x-www-form-urlencoded").body());
    }

    @Test
    void responseCookies() throws Exception {
        client.when(request().withPath("/cookie")).respond(response().withCookie(new Cookie("session", "abc")));
        assertEquals("session=abc", get("/cookie").headers().firstValue("Set-Cookie").orElseThrow());
    }

    @Test
    void lambdaResponseCallback() throws Exception {
        client.when(request().withPath("/callback"))
            .respond(req -> response().withStatusCode(207).withHeader("X-Echo", req.getFirstHeader("X-In")).withBody("cb:" + req.getPath().getValue()));
        var r = get("/callback", "X-In", "hello");
        assertEquals(207, r.statusCode());
        assertEquals("hello", r.headers().firstValue("X-Echo").orElseThrow());
        assertEquals("cb:/callback", r.body());
        assertTrue(r.headers().firstValue("WebSocketCorrelationId").isEmpty(), "correlation header is stripped");
    }

    @Test
    void lambdaCallbackThrowingGives404() throws Exception {
        client.when(request().withPath("/callback-error")).respond(req -> {
            throw new IllegalStateException("boom");
        });
        assertEquals(404, get("/callback-error").statusCode());
    }

    @Test
    void severalCallbacksAreKeptApart() throws Exception {
        client.when(request().withPath("/cb1")).respond(req -> response().withBody("one"));
        client.when(request().withPath("/cb2")).respond(req -> response().withBody("two"));
        assertEquals("one", get("/cb1").body());
        assertEquals("two", get("/cb2").body());
        assertEquals("one", get("/cb1").body());
    }
}
