package com.trevorism.gcloud.webapi.controller

import com.trevorism.gcloud.webapi.model.Identity
import com.trevorism.gcloud.webapi.model.TokenRequest
import com.trevorism.gcloud.webapi.service.*
import com.trevorism.secure.ClaimProperties
import com.trevorism.secure.ClaimsProvider
import com.trevorism.secure.Roles
import com.trevorism.secure.Secure
import io.swagger.annotations.Api
import io.swagger.annotations.ApiOperation

import javax.ws.rs.BadRequestException
import javax.ws.rs.Consumes
import javax.ws.rs.POST
import javax.ws.rs.Path
import javax.ws.rs.Produces
import javax.ws.rs.core.Context
import javax.ws.rs.core.HttpHeaders
import javax.ws.rs.core.MediaType

/**
 * @author tbrooks*
 */
@Api("Token Operations")
@Path("/token")
class TokenController {

    private UserCredentialService userCredentialService = new DefaultUserCredentialService()
    private AppRegistrationService appRegistrationService = new DefaultAppRegistrationService()
    private TokenService tokenService = new AccessTokenService()

    @ApiOperation(value = "Create a bearer token from valid credentials")
    @POST
    @Produces(MediaType.TEXT_PLAIN)
    @Consumes(MediaType.APPLICATION_JSON)
    String token(TokenRequest tokenRequest) {
        CredentialValidator service = appRegistrationService
        if (tokenRequest.type == TokenRequest.USER_TYPE) {
            service = userCredentialService
        }
        boolean valid = service.validateCredentials(tokenRequest.getId(), tokenRequest.password)

        if (valid) {
            Identity identity = service.getIdentity(tokenRequest.getId())
            return tokenService.issueToken(identity, tokenRequest.getAudience())
        }

        throw new BadRequestException("Unable to issue token")
    }

    @ApiOperation(value = "Create a new bearer token from an existing one. **Secure")
    @POST
    @Produces(MediaType.TEXT_PLAIN)
    @Consumes(MediaType.APPLICATION_JSON)
    @Secure(Roles.USER)
    @Path("refresh")
    String regenerateToken(@Context HttpHeaders httpheaders) {
        ClaimProperties properties = tokenService.getClaimProperties(getBearerToken(httpheaders))
        Identity identity = userCredentialService.getIdentity(properties.getSubject())
        tokenService.issueToken(identity, properties.getAudience())
    }

    private static String getBearerToken(HttpHeaders httpHeaders) {
        String bearerString = httpHeaders.getHeaderString(HttpHeaders.AUTHORIZATION)
        return bearerString.substring("bearer ".length())
    }

}
