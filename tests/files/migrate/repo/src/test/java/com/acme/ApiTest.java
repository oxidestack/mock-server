package com.acme;

import static org.mockserver.integration.ClientAndServer.startClientAndServer;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockserver.integration.ClientAndServer;

class ApiTest {

    private ClientAndServer mockServer;

    @BeforeEach
    void start() {
        mockServer = startClientAndServer(1080);
    }

    @AfterEach
    void stop() {
        mockServer.stop();
    }

    @Test
    void greets() {
        mockServer.when(request().withPath("/hello")).respond(response().withBody("hi"));
    }
}
