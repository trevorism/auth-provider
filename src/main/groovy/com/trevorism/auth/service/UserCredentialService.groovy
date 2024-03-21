package com.trevorism.auth.service

import com.trevorism.auth.model.ActivationRequest
import com.trevorism.auth.model.ChangePasswordRequest
import com.trevorism.auth.model.ForgotPasswordRequest
import com.trevorism.auth.model.Identity
import com.trevorism.auth.model.RegistrationRequest
import com.trevorism.auth.model.User
import io.micronaut.security.authentication.Authentication

interface UserCredentialService extends CredentialValidator {

    User getUser(String username)

    User deleteUser(String id)
    List<User> listUsers()

    boolean deactivateUser(User user)
    User getCurrentUser(Authentication authentication)

    //Quasi authenticated -- add additional logic to validate the request
    boolean activateUser(ActivationRequest activationRequest, Authentication authentication)
    boolean changePassword(ChangePasswordRequest changePasswordRequest, Authentication authentication)

    //Unauthenticated
    User registerUser(RegistrationRequest request)
    boolean validateRegistration(RegistrationRequest request)
    void forgotPassword(ForgotPasswordRequest forgotPasswordRequest)
}
