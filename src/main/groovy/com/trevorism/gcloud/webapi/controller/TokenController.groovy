package com.trevorism.gcloud.webapi.controller

import io.swagger.annotations.ApiOperation

import javax.ws.rs.GET
import javax.ws.rs.Path
import javax.ws.rs.Produces
import javax.ws.rs.core.MediaType

/**
 * @author tbrooks
 */
@Path("/token")
class TokenController {

    @ApiOperation(value = "Returns 'pong' if the application is alive")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    String token() {



    }


}
