package com.trevorism.gcloud.webapi.controller

import com.trevorism.gcloud.webapi.model.ActivationRequest
import com.trevorism.gcloud.webapi.model.User
import com.trevorism.gcloud.webapi.service.DefaultUserCredentialService
import com.trevorism.gcloud.webapi.service.UserCredentialService
import com.trevorism.secure.Secure
import io.swagger.annotations.Api
import io.swagger.annotations.ApiOperation

import javax.ws.rs.Consumes
import javax.ws.rs.DELETE
import javax.ws.rs.GET
import javax.ws.rs.POST
import javax.ws.rs.Path
import javax.ws.rs.PathParam
import javax.ws.rs.Produces
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
    @Secure
    List<User> listUsers() {
        userCredentialService.listUsers()
    }

    @ApiOperation(value = "Get a user by id **Secure")
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("{id}")
    @Secure
    User getUser(@PathParam("id") String id) {
        userCredentialService.getUser(id)
    }

    @ApiOperation(value = "Delete a user by id **Secure")
    @DELETE
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @Secure
    @Path("{username}")
    User removeUser(@PathParam("username") String username) {
        User user = userCredentialService.getIdentity(username)
        userCredentialService.deleteUser(user.id)
    }

    @ApiOperation(value = "Activate a user by username **Secure")
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @Secure
    @Path("activate")
    boolean activateUser(ActivationRequest activationRequest) {
        User user = userCredentialService.getIdentity(activationRequest.username)
        userCredentialService.activateUser(user, activationRequest.role)
    }

    @ApiOperation(value = "Deactivate a user by username **Secure")
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @Secure
    @Path("deactivate")
    boolean deactivateUser(ActivationRequest activationRequest) {
        User user = userCredentialService.getIdentity(activationRequest.username)
        userCredentialService.deactivateUser(user)
    }
}
