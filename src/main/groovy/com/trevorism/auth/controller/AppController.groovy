package com.trevorism.auth.controller

import com.trevorism.auth.model.App
import com.trevorism.auth.service.AppRegistrationService
import com.trevorism.secure.Roles
import com.trevorism.secure.Secure

import io.micronaut.http.MediaType
import io.micronaut.http.annotation.*
import io.micronaut.security.authentication.Authentication
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.tags.Tag

@Controller("/app")
class AppController {

    AppRegistrationService appRegistrationService

    AppController(AppRegistrationService appRegistrationService){
        this.appRegistrationService = appRegistrationService
    }

    @Tag(name = "App Operations")
    @Operation(summary = "Register a new app which generates a client Id **Secure")
    @Post(value = "/", produces = MediaType.APPLICATION_JSON, consumes = MediaType.APPLICATION_JSON)
    @Secure(Roles.TENANT_ADMIN)
    App registerApp(@Body App app, Authentication authentication) {
        appRegistrationService.registerApp(app, authentication)
    }

    @Tag(name = "App Operations")
    @Operation(summary = "Returns a list of all apps **Secure")
    @Get(value = "/", produces = MediaType.APPLICATION_JSON)
    @Secure(Roles.TENANT_ADMIN)
    List<App> listApps() {
        appRegistrationService.listRegisteredApps()
    }

    @Tag(name = "App Operations")
    @Operation(summary = "Get an app by Id **Secure")
    @Get(value = "/{id}", produces = MediaType.APPLICATION_JSON)
    @Secure(Roles.TENANT_ADMIN)
    App getApp(String id) {
        appRegistrationService.getRegisteredApp(id)
    }

    @Tag(name = "App Operations")
    @Operation(summary = "Remove an app by Id **Secure")
    @Delete(value = "/{id}", produces = MediaType.APPLICATION_JSON)
    @Secure(Roles.TENANT_ADMIN)
    App removeApp(String id) {
        App app = appRegistrationService.getRegisteredApp(id)
        appRegistrationService.removeRegisteredApp(app.id)
    }

    @Tag(name = "App Operations")
    @Operation(summary = "Update the app secret from an apps clientId **Secure")
    @Put(value = "{clientId}/secret", produces = MediaType.APPLICATION_JSON)
    @Secure(Roles.TENANT_ADMIN)
    String updateAppSecret(String clientId, Authentication authentication) {
        App app = appRegistrationService.getIdentity(clientId) as App
        appRegistrationService.generateClientSecret(app, authentication)
    }
}
