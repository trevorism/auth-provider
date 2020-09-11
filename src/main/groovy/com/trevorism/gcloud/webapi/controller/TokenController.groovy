package com.trevorism.gcloud.webapi.controller

import com.trevorism.gcloud.webapi.model.Identity
import com.trevorism.gcloud.webapi.model.TokenRequest
import com.trevorism.gcloud.webapi.service.AccessTokenService
import com.trevorism.gcloud.webapi.service.AppRegistrationService
import com.trevorism.gcloud.webapi.service.CredentialValidator
import com.trevorism.gcloud.webapi.service.DefaultAppRegistrationService
import com.trevorism.gcloud.webapi.service.DefaultUserCredentialService
import com.trevorism.gcloud.webapi.service.TokenService
import com.trevorism.gcloud.webapi.service.UserCredentialService
import io.swagger.annotations.Api

import javax.ws.rs.Consumes
import javax.ws.rs.POST
import javax.ws.rs.Path
import javax.ws.rs.Produces
import javax.ws.rs.core.MediaType

/**
 * @author tbrooks
 *
 */
@Api("Token Operations")
@Path("/token")
class TokenController {

    private UserCredentialService userCredentialService = new DefaultUserCredentialService()
    private AppRegistrationService appRegistrationService = new DefaultAppRegistrationService()
    private TokenService tokenService = new AccessTokenService()

    @POST
    @Produces(MediaType.TEXT_PLAIN)
    @Consumes(MediaType.APPLICATION_JSON)
    String token(TokenRequest tokenRequest) {
        CredentialValidator service = appRegistrationService
        if(tokenRequest.type == TokenRequest.USER_TYPE){
            service = userCredentialService
        }
        boolean valid = service.validateCredentials(tokenRequest.getId(), tokenRequest.password)

        if(valid){
            Identity identity = service.getIdentity(tokenRequest.getId())
            return tokenService.issueToken(identity, tokenRequest)
        }

        return null
    }

}
