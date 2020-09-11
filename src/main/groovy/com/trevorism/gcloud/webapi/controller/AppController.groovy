package com.trevorism.gcloud.webapi.controller

import com.trevorism.gcloud.webapi.model.App
import com.trevorism.gcloud.webapi.model.Identity
import com.trevorism.gcloud.webapi.model.User
import com.trevorism.gcloud.webapi.service.AppRegistrationService
import com.trevorism.gcloud.webapi.service.DefaultAppRegistrationService
import io.swagger.annotations.Api

import javax.ws.rs.*
import javax.ws.rs.core.MediaType

@Api("App Operations")
@Path("/app")
class AppController {

    AppRegistrationService appRegistrationService = new DefaultAppRegistrationService()

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    App registerApp(App app) {
        appRegistrationService.registerApp(app)
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    List<App> listUsers() {
        appRegistrationService.listRegisteredApps()
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("{clientId}")
    App getAppByClientId(@PathParam("clientId") String clientId) {
        appRegistrationService.getIdentity(clientId)
    }

    @DELETE
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("{clientId}")
    App removeUser(@PathParam("clientId") String clientId) {
        App app = appRegistrationService.getIdentity(clientId)
        appRegistrationService.removeRegisteredApp(app.id)
    }

    @PUT
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("{clientId}/secret")
    String updateAppSecret(@PathParam("clientId") String clientId) {
        App app = appRegistrationService.getIdentity(clientId)
        appRegistrationService.generateClientSecret(app)
    }
}
