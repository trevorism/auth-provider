package com.trevorism.gcloud.webapi.service

import com.trevorism.gcloud.webapi.model.Identity
import com.trevorism.gcloud.webapi.model.User

interface UserCredentialService extends CredentialValidator {

    User getUser(String username)
    User deleteUser(String id)
    List<User> listUsers()

    User registerUser(User user)
    boolean validateRegistration(User user)

    boolean activateUser(User user, String role)
    boolean deactivateUser(User user)

    boolean changePassword(Identity identity, String currentPassword, String newPassword)
    void forgotPassword(Identity identity)
}
