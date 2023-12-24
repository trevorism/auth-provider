package com.trevorism.auth.errors

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.server.exceptions.ExceptionHandler
import io.micronaut.http.HttpResponse
import io.micronaut.http.annotation.Produces

@Produces
@jakarta.inject.Singleton
@Requires(classes = [ AuthException, HttpResponse ] )
class AuthExceptionHandler implements ExceptionHandler<AuthException, HttpResponse> {

    @Override
    HttpResponse handle(HttpRequest request, AuthException exception) {
        return HttpResponse.badRequest(exception.message)
    }
}
