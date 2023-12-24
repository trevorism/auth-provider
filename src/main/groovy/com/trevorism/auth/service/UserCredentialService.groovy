package com.trevorism.auth.service

import com.trevorism.auth.model.Identity
import com.trevorism.auth.model.User
import io.micronaut.security.authentication.Authentication

interface UserCredentialService extends CredentialValidator {

    User getUser(String username)

    User deleteUser(String id)
    List<User> listUsers()

    User registerUser(User user)
    boolean validateRegistration(User user)

    boolean activateUser(User user, boolean isAdmin)
    boolean deactivateUser(User user)

    boolean changePassword(Identity identity, String currentPassword, String newPassword)
    void forgotPassword(Identity identity)

    User getCurrentUser(Authentication authentication)
}
