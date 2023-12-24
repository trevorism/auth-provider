package com.trevorism.auth.controller

import com.trevorism.ClaimProperties
import com.trevorism.auth.model.InternalTokenRequest
import com.trevorism.auth.service.AppRegistrationService
import com.trevorism.auth.service.CredentialValidator
import com.trevorism.auth.service.TokenService
import com.trevorism.auth.model.Identity
import com.trevorism.auth.model.TokenRequest
import com.trevorism.auth.service.UserCredentialService
import com.trevorism.secure.Roles
import com.trevorism.secure.Secure
import io.micronaut.http.HttpHeaders
import io.micronaut.http.HttpStatus
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Body
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Post
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.inject.Inject
import org.apache.hc.client5.http.HttpResponseException
import org.slf4j.Logger
import org.slf4j.LoggerFactory

@Controller("/token")
class TokenController {

    private static final Logger log = LoggerFactory.getLogger(TokenController)

    @Inject
    private UserCredentialService userCredentialService
    @Inject
    private AppRegistrationService appRegistrationService
    @Inject
    private TokenService tokenService

    @Tag(name = "Token Operations")
    @Operation(summary = "Create a bearer token from valid credentials")
    @Post(value = "/", produces = MediaType.TEXT_PLAIN, consumes = MediaType.APPLICATION_JSON)
    String token(@Body TokenRequest tokenRequest) {
        CredentialValidator service = appRegistrationService
        if (tokenRequest.type == TokenRequest.USER_TYPE) {
            service = userCredentialService
        }
        boolean valid = service.validateCredentials(tokenRequest.getId(), tokenRequest.password)

        if (valid) {
            Identity identity = service.getIdentity(tokenRequest.getId())
            log.info("Issuing token for ${identity.id}")
            return tokenService.issueToken(identity, tokenRequest.getAudience())
        }

        throw new HttpResponseException(HttpStatus.BAD_REQUEST.getCode(), "Unable to issue token")
    }


    @Tag(name = "Token Operations")
    @Operation(summary = "Create a new bearer token from an existing one. **Secure")
    @Post(value = "/refresh", produces = MediaType.TEXT_PLAIN, consumes = MediaType.APPLICATION_JSON)
    @Secure(Roles.USER)
    String regenerateToken(HttpHeaders httpheaders) {
        ClaimProperties properties = tokenService.getClaimProperties(getBearerToken(httpheaders))
        Identity identity = userCredentialService.getIdentity(properties.getSubject())
        tokenService.issueToken(identity, properties.getAudience())
    }

    @Tag(name = "Token Operations")
    @Operation(summary = "Create an internal token. **Secure")
    @Post(value = "/internal", produces = MediaType.TEXT_PLAIN, consumes = MediaType.APPLICATION_JSON)
    @Secure(Roles.SYSTEM)
    String createInternalToken(@Body InternalTokenRequest tokenRequest) {
        if(!tokenRequest.subject) {
            throw new HttpResponseException(HttpStatus.BAD_REQUEST.getCode(), "Unable to issue token")
        }

        Identity identity = appRegistrationService.getIdentity(tokenRequest.getSubject())
        tokenService.issueInternalToken(identity, tokenRequest.getAudience(), tokenRequest.tenantId)
    }

    private static String getBearerToken(HttpHeaders httpHeaders) {
        String bearerString = httpHeaders.getValue(HttpHeaders.AUTHORIZATION)
        return bearerString.substring("bearer ".length())
    }

}
