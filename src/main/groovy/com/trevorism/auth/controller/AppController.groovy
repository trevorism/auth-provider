package com.trevorism.auth.controller

import com.trevorism.auth.model.App
import com.trevorism.auth.service.AppRegistrationService
import com.trevorism.secure.Roles
import com.trevorism.secure.Secure

import io.micronaut.http.MediaType
import io.micronaut.http.annotation.*
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.inject.Inject

@Controller("/app")
class AppController {

    @Inject
    private AppRegistrationService appRegistrationService

    @Tag(name = "App Operations")
    @Operation(summary = "Register a new app which generates a client Id **Secure")
    @Post(value = "/", produces = MediaType.APPLICATION_JSON, consumes = MediaType.APPLICATION_JSON)
    @Secure(Roles.SYSTEM)
    App registerApp(@Body App app) {
        appRegistrationService.registerApp(app)
    }

    @Tag(name = "App Operations")
    @Operation(summary = "Returns a list of all apps **Secure")
    @Get(value = "/", produces = MediaType.APPLICATION_JSON)
    @Secure(Roles.SYSTEM)
    List<App> listApps() {
        appRegistrationService.listRegisteredApps()
    }

    @Tag(name = "App Operations")
    @Operation(summary = "Get an app by Id **Secure")
    @Get(value = "/{id}", produces = MediaType.APPLICATION_JSON)
    @Secure(Roles.SYSTEM)
    App getApp(String id) {
        appRegistrationService.getRegisteredApp(id)
    }

    @Tag(name = "App Operations")
    @Operation(summary = "Remove an app by Id **Secure")
    @Delete(value = "/{id}", produces = MediaType.APPLICATION_JSON)
    @Secure(Roles.SYSTEM)
    App removeApp(String id) {
        App app = appRegistrationService.getRegisteredApp(id)
        appRegistrationService.removeRegisteredApp(app.id)
    }

    @Tag(name = "App Operations")
    @Operation(summary = "Update the app secret from an apps clientId **Secure")
    @Put(value = "{clientId}/secret", produces = MediaType.APPLICATION_JSON)
    @Secure(Roles.ADMIN)
    String updateAppSecret(String clientId) {
        App app = appRegistrationService.getIdentity(clientId) as App
        appRegistrationService.generateClientSecret(app)
    }
}
