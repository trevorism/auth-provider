package com.trevorism.auth.controller

import com.trevorism.auth.model.User
import com.trevorism.auth.service.DefaultUserCredentialService
import com.trevorism.auth.service.UserCredentialService
import com.trevorism.secure.Roles
import com.trevorism.secure.Secure
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Body
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Post
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.tags.Tag

@Controller("/tenantuser")
class TenantUserController {

    UserCredentialService userCredentialService = new DefaultUserCredentialService()

    @Tag(name = "User Operations")
    @Operation(summary = "Register a user with username, password, and email")
    @Post(value = "/{tenantGuid}", produces = MediaType.APPLICATION_JSON, consumes = MediaType.APPLICATION_JSON)
    @Secure(Roles.TENANT_ADMIN)
    User registerUser(String tenantGuid, @Body User user) {
        user.tenantGuid = tenantGuid
        userCredentialService.registerUser(user)
    }

}
