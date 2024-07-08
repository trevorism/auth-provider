package com.trevorism.auth.controller

import com.trevorism.auth.model.*
import com.trevorism.auth.service.TenantAwareUserService
import com.trevorism.auth.service.UserService
import com.trevorism.secure.Permissions
import com.trevorism.secure.Roles
import com.trevorism.secure.Secure
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.*
import io.micronaut.security.authentication.Authentication
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.inject.Inject

@Controller("/user")
class UserController {

    @Inject
    private UserService passThruUserService

    @Inject
    private TenantAwareUserService tenantAwareUserService

    @Tag(name = "User Operations")
    @Operation(summary = "Returns the list of all users **Secure")
    @Get(value = "/", produces = MediaType.APPLICATION_JSON)
    @Secure(Roles.TENANT_ADMIN)
    List<User> listUsers() {
        passThruUserService.listUsers()
    }

    @Tag(name = "User Operations")
    @Operation(summary = "Get a user by id **Secure")
    @Get(value = "/{id}", produces = MediaType.APPLICATION_JSON)
    @Secure(value = Roles.USER, permissions = Permissions.READ)
    User getUser(String id) {
        passThruUserService.getUser(id)
    }

    @Tag(name = "User Operations")
    @Operation(summary = "Delete a user by id **Secure")
    @Delete(value = "/{username}", produces = MediaType.APPLICATION_JSON)
    @Secure(Roles.TENANT_ADMIN)
    User removeUser(String username) {
        User user = passThruUserService.getIdentity(username) as User
        passThruUserService.deleteUser(user.id)
    }

    @Tag(name = "User Operations")
    @Operation(summary = "Register a user with username, password, and email")
    @Post(value = "/", produces = MediaType.APPLICATION_JSON, consumes = MediaType.APPLICATION_JSON)
    User registerUser(@Body RegistrationRequest user) {

        tenantAwareUserService.registerUser(user)
    }

    @Tag(name = "User Operations")
    @Operation(summary = "Reset Password **Secure")
    @Post(value = "/reset", produces = MediaType.APPLICATION_JSON, consumes = MediaType.APPLICATION_JSON)
    boolean resetPassword(@Body ForgotPasswordRequest forgotPasswordRequest) {
        try {
            tenantAwareUserService.forgotPassword(forgotPasswordRequest)
        } catch (Exception ignored) {
            return false
        }
        return true
    }

    @Tag(name = "User Operations")
    @Operation(summary = "Change Password **Secure")
    @Post(value = "/change", produces = MediaType.APPLICATION_JSON, consumes = MediaType.APPLICATION_JSON)
    boolean changePassword(@Body ChangePasswordRequest changePasswordRequest) {
        try {
            tenantAwareUserService.changePassword(changePasswordRequest)
        } catch (Exception ignored) {
            return false
        }
        return true
    }

    @Tag(name = "User Operations")
    @Operation(summary = "Get the current user **Secure")
    @Get(value = "/me", produces = MediaType.APPLICATION_JSON)
    @Secure(value = Roles.USER, permissions = Permissions.READ)
    User getCurrentUser(Authentication authentication) {
        tenantAwareUserService.getCurrentUser(authentication)
    }

    @Tag(name = "User Operations")
    @Operation(summary = "Activate a user by username **Secure")
    @Post(value = "/activate", produces = MediaType.APPLICATION_JSON, consumes = MediaType.APPLICATION_JSON)
    @Secure(Roles.TENANT_ADMIN)
    boolean activateUser(@Body ActivationRequest activationRequest, Authentication authentication) {
        tenantAwareUserService.activateUser(activationRequest, authentication)
    }

    @Tag(name = "User Operations")
    @Operation(summary = "Deactivate a user by username **Secure")
    @Post(value = "/deactivate", produces = MediaType.APPLICATION_JSON, consumes = MediaType.APPLICATION_JSON)
    @Secure(Roles.TENANT_ADMIN)
    boolean deactivateUser(@Body ActivationRequest activationRequest, Authentication authentication) {
        tenantAwareUserService.deactivateUser(activationRequest, authentication)
    }

}
