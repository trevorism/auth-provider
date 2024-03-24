package com.trevorism.auth.errors

import io.micronaut.context.annotation.Requires
import io.micronaut.http.HttpRequest
import io.micronaut.http.server.exceptions.ExceptionHandler
import io.micronaut.http.HttpResponse
import io.micronaut.http.annotation.Produces
import org.slf4j.Logger
import org.slf4j.LoggerFactory

@Produces
@jakarta.inject.Singleton
@Requires(classes = [ AuthException, HttpResponse ] )
class AuthExceptionHandler implements ExceptionHandler<AuthException, HttpResponse> {

    private static final Logger log = LoggerFactory.getLogger(AuthExceptionHandler)

    @Override
    HttpResponse handle(HttpRequest request, AuthException exception) {
        log.error("Auth exception", exception)
        return HttpResponse.badRequest(exception.message)
    }
}
