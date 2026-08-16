package com.trevorism.auth.errors

import io.micronaut.http.HttpRequest
import io.micronaut.http.HttpResponse
import io.micronaut.http.HttpStatus
import org.junit.jupiter.api.Test

class AuthExceptionHandlerTest {

    @Test
    void testReturnsBadRequestWithTheExceptionMessage() {
        AuthExceptionHandler handler = new AuthExceptionHandler()
        HttpResponse response = handler.handle(HttpRequest.GET("/token"), new AuthException("Invalid refresh token"))

        assert response.status() == HttpStatus.BAD_REQUEST
        assert response.body() == "Invalid refresh token"
    }
}
