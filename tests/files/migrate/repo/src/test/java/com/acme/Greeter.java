package com.acme;

import static org.mockserver.model.HttpResponse.response;

import org.mockserver.mock.action.ExpectationResponseCallback;
import org.mockserver.model.HttpRequest;
import org.mockserver.model.HttpResponse;

public class Greeter implements ExpectationResponseCallback {
    @Override
    public HttpResponse handle(HttpRequest request) {
        return response().withBody("hello " + request.getPath());
    }
}
