package com.trevorism.auth.controller

import com.trevorism.ClaimProperties
import com.trevorism.auth.service.AccessTokenService
import com.trevorism.auth.service.AppRegistrationService
import com.trevorism.auth.service.CredentialValidator
import com.trevorism.auth.service.DefaultAppRegistrationService
import com.trevorism.auth.service.DefaultUserCredentialService
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
import org.apache.hc.client5.http.HttpResponseException

@Controller("/token")
class TokenController {

    private UserCredentialService userCredentialService = new DefaultUserCredentialService()
    private AppRegistrationService appRegistrationService = new DefaultAppRegistrationService()
    private TokenService tokenService = new AccessTokenService()

    @Tag(name = "Token Operations")
    @Operation(summary = "Create a bearer token from valid credentials")
    @Post(value = "/", produces = MediaType.APPLICATION_JSON, consumes = MediaType.APPLICATION_JSON)
    String token(@Body TokenRequest tokenRequest) {
        CredentialValidator service = appRegistrationService
        if (tokenRequest.type == TokenRequest.USER_TYPE) {
            service = userCredentialService
        }
        boolean valid = service.validateCredentials(tokenRequest.getId(), tokenRequest.password)

        if (valid) {
            Identity identity = service.getIdentity(tokenRequest.getId())
            return tokenService.issueToken(identity, tokenRequest.getAudience())
        }

        throw new HttpResponseException(HttpStatus.BAD_REQUEST.getCode(), "Unable to issue token")
    }


    @Tag(name = "Token Operations")
    @Operation(summary = "Create a new bearer token from an existing one. **Secure")
    @Post(value = "/refresh", produces = MediaType.APPLICATION_JSON, consumes = MediaType.APPLICATION_JSON)
    @Secure(Roles.USER)
    String regenerateToken(HttpHeaders httpheaders) {
        ClaimProperties properties = tokenService.getClaimProperties(getBearerToken(httpheaders))
        Identity identity = userCredentialService.getIdentity(properties.getSubject())
        tokenService.issueToken(identity, properties.getAudience())
    }

    private static String getBearerToken(HttpHeaders httpHeaders) {
        String bearerString = httpHeaders.getValue(HttpHeaders.AUTHORIZATION)
        return bearerString.substring("bearer ".length())
    }

}
