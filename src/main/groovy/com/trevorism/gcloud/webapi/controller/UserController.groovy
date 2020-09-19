package com.trevorism.gcloud.webapi.controller

import com.trevorism.gcloud.webapi.model.ActivationRequest
import com.trevorism.gcloud.webapi.model.ChangePasswordRequest
import com.trevorism.gcloud.webapi.model.User
import com.trevorism.gcloud.webapi.service.DefaultUserCredentialService
import com.trevorism.gcloud.webapi.service.UserCredentialService
import com.trevorism.secure.Roles
import com.trevorism.secure.Secure
import io.swagger.annotations.Api
import io.swagger.annotations.ApiOperation

import javax.ws.rs.*
import javax.ws.rs.core.MediaType

@Api("User Operations")
@Path("/user")
class UserController {

    UserCredentialService userCredentialService = new DefaultUserCredentialService()

    @ApiOperation(value = "Register a user with username, password, and email")
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    User registerUser(User user) {
        userCredentialService.registerUser(user)
    }

    @ApiOperation(value = "Returns the list of all users **Secure")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Secure(Roles.SYSTEM)
    List<User> listUsers() {
        userCredentialService.listUsers()
    }

    @ApiOperation(value = "Get a user by id **Secure")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("{id}")
    @Secure(Roles.USER)
    User getUser(@PathParam("id") String id) {
        userCredentialService.getUser(id)
    }

    @ApiOperation(value = "Delete a user by id **Secure")
    @DELETE
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @Secure(Roles.SYSTEM)
    @Path("{username}")
    User removeUser(@PathParam("username") String username) {
        User user = userCredentialService.getIdentity(username) as User
        userCredentialService.deleteUser(user.id)
    }

    @ApiOperation(value = "Activate a user by username **Secure")
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @Secure(Roles.ADMIN)
    @Path("activate")
    boolean activateUser(ActivationRequest activationRequest) {
        User user = userCredentialService.getIdentity(activationRequest.username) as User
        userCredentialService.activateUser(user, activationRequest.isAdmin)
    }

    @ApiOperation(value = "Deactivate a user by username **Secure")
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @Secure(Roles.SYSTEM)
    @Path("deactivate")
    boolean deactivateUser(ActivationRequest activationRequest) {
        User user = userCredentialService.getIdentity(activationRequest.username) as User
        userCredentialService.deactivateUser(user)
    }

    @ApiOperation(value = "Reset Password **Secure")
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @Secure(Roles.SYSTEM)
    @Path("reset")
    boolean resetPassword(ActivationRequest activationRequest) {
        try {
            userCredentialService.forgotPassword(new User(username: activationRequest.username))
        } catch (Exception ignored) {
            return false
        }
        return true
    }

    @ApiOperation(value = "Change Password **Secure")
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @Secure(Roles.USER)
    @Path("change")
    boolean changePassword(ChangePasswordRequest changePasswordRequest) {
        try {
            User user = userCredentialService.getIdentity(changePasswordRequest.username) as User
            userCredentialService.changePassword(user, changePasswordRequest.currentPassword, changePasswordRequest.desiredPassword)
        } catch (Exception ignored) {
            return false
        }
        return true
    }
}
