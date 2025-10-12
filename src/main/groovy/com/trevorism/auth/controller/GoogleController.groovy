package com.trevorism.auth.controller

import com.trevorism.auth.errors.AuthException
import com.trevorism.auth.model.Oauth2Tokens
import com.trevorism.auth.model.SupportedOauth2Provider
import com.trevorism.auth.service.TokenService
import com.trevorism.auth.service.oauth.Oauth2Parser
import com.trevorism.secure.Roles
import com.trevorism.secure.Secure
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jws
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Body
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Post
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.inject.Inject
import jakarta.inject.Named
import org.slf4j.Logger
import org.slf4j.LoggerFactory

@Controller("/google")
class GoogleController {

    private static final Logger log = LoggerFactory.getLogger(GoogleController)

    @Inject
    private TokenService tokenService

    @Inject
    @Named("google")
    private Oauth2Parser oauth2Parser

    @Tag(name = "Google Operations")
    @Operation(summary = "Create a token from a validated Google token")
    @Post(value = "/", produces = MediaType.TEXT_PLAIN, consumes = MediaType.APPLICATION_JSON)
    String createToken(@Body Oauth2Tokens tokens) {
        try {
            Jws<Claims> claims = oauth2Parser.parse(tokens)
            return tokenService.issueTokenFromOauthProvider(SupportedOauth2Provider.Google, claims, tokens.tenantId)
        }
        catch (Exception e) {
            log.warn("Error validating Google token", e)
            throw new AuthException("Unable to issue token, unable to authenticate with Google")
        }
    }

    @Tag(name = "Google Operations")
    @Operation(summary = "Get token claims from a validated Google token **Secure")
    @Post(value = "/claims", produces = MediaType.APPLICATION_JSON, consumes = MediaType.APPLICATION_JSON)
    @Secure(Roles.SYSTEM)
    Map fetchClaims(@Body Oauth2Tokens tokens) {
        try {
            Jws<Claims> claims = oauth2Parser.parse(tokens)
            return claims.payload
        }
        catch (Exception e) {
            log.warn("Error validating Google token", e)
            throw new AuthException("Unable to issue token, unable to authenticate with Google")
        }
    }

}