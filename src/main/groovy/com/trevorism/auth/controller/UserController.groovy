package com.trevorism.auth.controller

import com.trevorism.auth.model.ActivationRequest
import com.trevorism.auth.model.ChangePasswordRequest
import com.trevorism.auth.model.User
import com.trevorism.auth.service.DefaultUserCredentialService
import com.trevorism.auth.service.UserCredentialService
import com.trevorism.secure.Roles
import com.trevorism.secure.Secure
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.*
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.inject.Inject

@Controller("/user")
class UserController {

    @Inject
    private UserCredentialService userCredentialService

    @Tag(name = "User Operations")
    @Operation(summary = "Register a user with username, password, and email")
    @Post(value = "/", produces = MediaType.APPLICATION_JSON, consumes = MediaType.APPLICATION_JSON)
    User registerUser(@Body User user) {
        userCredentialService.registerUser(user)
    }

    @Tag(name = "User Operations")
    @Operation(summary = "Returns the list of all users **Secure")
    @Get(value = "/", produces = MediaType.APPLICATION_JSON)
    @Secure(Roles.SYSTEM)
    List<User> listUsers() {
        userCredentialService.listUsers()
    }

    @Tag(name = "User Operations")
    @Operation(summary = "Get a user by id **Secure")
    @Get(value = "/{id}", produces = MediaType.APPLICATION_JSON)
    @Secure(Roles.USER)
    User getUser(String id) {
        userCredentialService.getUser(id)
    }

    @Tag(name = "User Operations")
    @Operation(summary = "Delete a user by id **Secure")
    @Delete(value = "/{username}", produces = MediaType.APPLICATION_JSON)
    @Secure(Roles.SYSTEM)
    User removeUser(String username) {
        User user = userCredentialService.getIdentity(username) as User
        userCredentialService.deleteUser(user.id)
    }

    @Tag(name = "User Operations")
    @Operation(summary = "Activate a user by username **Secure")
    @Post(value = "/activate", produces = MediaType.APPLICATION_JSON, consumes = MediaType.APPLICATION_JSON)
    @Secure(Roles.ADMIN)
    boolean activateUser(@Body ActivationRequest activationRequest) {
        User user = userCredentialService.getIdentity(activationRequest.username) as User
        userCredentialService.activateUser(user, activationRequest.isAdmin)
    }

    @Tag(name = "User Operations")
    @Operation(summary = "Deactivate a user by username **Secure")
    @Post(value = "/deactivate", produces = MediaType.APPLICATION_JSON, consumes = MediaType.APPLICATION_JSON)
    @Secure(Roles.SYSTEM)
    boolean deactivateUser(@Body ActivationRequest activationRequest) {
        User user = userCredentialService.getIdentity(activationRequest.username) as User
        userCredentialService.deactivateUser(user)
    }

    @Tag(name = "User Operations")
    @Operation(summary = "Reset Password **Secure")
    @Post(value = "/reset", produces = MediaType.APPLICATION_JSON, consumes = MediaType.APPLICATION_JSON)
    @Secure(Roles.SYSTEM)
    boolean resetPassword(@Body ActivationRequest activationRequest) {
        try {
            userCredentialService.forgotPassword(new User(username: activationRequest.username))
        } catch (Exception ignored) {
            return false
        }
        return true
    }

    @Tag(name = "User Operations")
    @Operation(summary = "Change Password **Secure")
    @Post(value = "/change", produces = MediaType.APPLICATION_JSON, consumes = MediaType.APPLICATION_JSON)
    @Secure(Roles.USER)
    boolean changePassword(@Body ChangePasswordRequest changePasswordRequest) {
        try {
            User user = userCredentialService.getIdentity(changePasswordRequest.username) as User
            userCredentialService.changePassword(user, changePasswordRequest.currentPassword, changePasswordRequest.desiredPassword)
        } catch (Exception ignored) {
            return false
        }
        return true
    }
}