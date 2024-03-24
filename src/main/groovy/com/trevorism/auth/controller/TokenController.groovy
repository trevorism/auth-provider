package com.trevorism.auth.controller

import com.trevorism.ClaimProperties
import com.trevorism.auth.errors.AuthException
import com.trevorism.auth.model.InternalTokenRequest
import com.trevorism.auth.service.AppRegistrationService

import com.trevorism.auth.service.TenantUserService
import com.trevorism.auth.service.TokenService
import com.trevorism.auth.model.Identity
import com.trevorism.auth.model.TokenRequest
import com.trevorism.secure.Roles
import com.trevorism.secure.Secure
import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Body
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Post
import io.micronaut.security.authentication.Authentication
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.inject.Inject
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.time.Instant
import java.time.temporal.ChronoUnit

@Controller("/token")
class TokenController {

    private static final Logger log = LoggerFactory.getLogger(TokenController)

    @Inject
    private TokenService tokenService

    @Tag(name = "Token Operations")
    @Operation(summary = "Create a bearer token from valid credentials")
    @Post(value = "/", produces = MediaType.TEXT_PLAIN, consumes = MediaType.APPLICATION_JSON)
    String getToken(@Body TokenRequest tokenRequest) {
        Identity identity = tokenService.getValidatedIdentity(tokenRequest)

        if (identity) {
            log.info("Issuing token for ${identity.id}")
            return tokenService.issueToken(identity, tokenRequest.getAudience())
        }

        throw new AuthException("Unable to issue token, unable to authenticate ${tokenRequest.id}")
    }

    @Tag(name = "Token Operations")
    @Operation(summary = "Create an internal token. **Secure")
    @Post(value = "/internal", produces = MediaType.TEXT_PLAIN, consumes = MediaType.APPLICATION_JSON)
    @Secure(Roles.SYSTEM)
    String createInternalToken(@Body InternalTokenRequest internalTokenRequest, Authentication authentication) {
        if(!internalTokenRequest.subject) {
            throw new AuthException("Unable to issue token, missing subject")
        }
        Identity identity = createIdentityFromInternalTokenRequest(authentication, internalTokenRequest)
        tokenService.issueInternalToken(identity, internalTokenRequest.getAudience(), internalTokenRequest.tenantId)
    }

    private static Identity createIdentityFromInternalTokenRequest(authentication, internalTokenRequest) {
        Identity identity = new Identity() {
            @Override
            String getId() {
                authentication.getAttributes().get("id")
            }

            @Override
            String getIdentifer() {
                return internalTokenRequest.subject
            }

            @Override
            boolean isActive() {
                return true
            }

            @Override
            String getTenantGuid() {
                return authentication.getAttributes().get("tenant")
            }

            @Override
            Date getDateCreated() {
                return new Date()
            }

            @Override
            Date getDateExpired() {
                return Date.from(Instant.now().plus(1, ChronoUnit.HOURS))
            }
        }
        return identity
    }

}
