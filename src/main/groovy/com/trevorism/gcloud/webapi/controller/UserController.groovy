package com.trevorism.gcloud.webapi.controller

import com.trevorism.gcloud.webapi.model.Identity
import com.trevorism.gcloud.webapi.model.User
import com.trevorism.gcloud.webapi.service.DefaultUserCredentialService
import com.trevorism.gcloud.webapi.service.UserCredentialService
import io.swagger.annotations.Api

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

    @POST
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    User registerUser(User user) {
        userCredentialService.registerUser(user)
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    List<User> listUsers() {
        userCredentialService.listUsers()
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("{username}")
    Identity getUser(@PathParam("username") String username) {
        userCredentialService.getIdentity(username)
    }

    @DELETE
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("{username}")
    User removeUser(@PathParam("username") String username) {
        User user = userCredentialService.getIdentity(username)
        userCredentialService.deleteUser(user.id)
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("{username}/activate")
    boolean activateUser(@PathParam("username") String username) {
        User user = userCredentialService.getIdentity(username)
        userCredentialService.activateUser(user)
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @Path("{username}/deactivate")
    boolean deactivateUser(@PathParam("username") String username) {
        User user = userCredentialService.getIdentity(username)
        userCredentialService.deactivateUser(user)
    }
}
