package com.trevorism.gcloud.webapi.controller

import com.trevorism.gcloud.webapi.model.User
import com.trevorism.gcloud.webapi.service.AccessTokenService
import com.trevorism.gcloud.webapi.service.DefaultUserCredentialService
import com.trevorism.gcloud.webapi.service.TokenService
import com.trevorism.gcloud.webapi.service.UserCredentialService

import javax.ws.rs.Consumes
import javax.ws.rs.POST
import javax.ws.rs.Path
import javax.ws.rs.Produces
import javax.ws.rs.core.MediaType

/**
 * @author tbrooks
 *
 */
@Path("/authorize")
class CredentialsController {


    private UserCredentialService service = new DefaultUserCredentialService()
    private TokenService tokenService = new AccessTokenService()

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    String token(User userCredential) {
        boolean valid = service.validateCredentials(userCredential.username, userCredential.password)

        if(valid){
            return tokenService.issueToken(userCredential)
        }

        return null
    }

}
