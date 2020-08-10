package com.trevorism.gcloud.webapi.service

import com.trevorism.gcloud.webapi.model.User

interface UserCredentialService {

    User getUser(String username)
    User deleteUser(String id)
    List<User> listUsers()

    User registerUser(User user)

    boolean validateCredentials(String username, String password)

    boolean validateRegistration(User user)
}
