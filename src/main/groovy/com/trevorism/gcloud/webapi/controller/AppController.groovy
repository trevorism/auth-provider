package com.trevorism.gcloud.webapi.controller

import com.trevorism.gcloud.webapi.model.App
import com.trevorism.gcloud.webapi.service.AppRegistrationService
import com.trevorism.gcloud.webapi.service.DefaultAppRegistrationService
import com.trevorism.secure.Secure
import io.swagger.annotations.Api
import io.swagger.annotations.ApiOperation

import javax.ws.rs.*
import javax.ws.rs.core.MediaType

@Api("App Operations")
@Path("/app")
class AppController {

    private AppRegistrationService appRegistrationService = new DefaultAppRegistrationService()

    @ApiOperation(value = "Register a new app which generates a client Id")
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    App registerApp(App app) {
        appRegistrationService.registerApp(app)
    }

    @ApiOperation(value = "Returns a list of all apps **Secure")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Secure
    List<App> listUsers() {
        appRegistrationService.listRegisteredApps()
    }

    @ApiOperation(value = "Get an app by Id **Secure")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("{id}")
    @Secure
    App getApp(@PathParam("id") String id) {
        appRegistrationService.getRegisteredApp(id)
    }

    @ApiOperation(value = "Remove an app by Id **Secure")
    @DELETE
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("{id}")
    @Secure
    App removeApp(@PathParam("id") String id) {
        App app = appRegistrationService.getRegisteredApp(id)
        appRegistrationService.removeRegisteredApp(app.id)
    }

    @ApiOperation(value = "Update the app secret from an apps clientId **Secure")
    @PUT
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("{clientId}/secret")
    @Secure
    String updateAppSecret(@PathParam("clientId") String clientId) {
        App app = appRegistrationService.getIdentity(clientId)
        appRegistrationService.generateClientSecret(app)
    }
}
