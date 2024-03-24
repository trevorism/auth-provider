package com.trevorism.auth.service

import com.trevorism.auth.model.ActivationRequest
import com.trevorism.auth.model.ChangePasswordRequest
import com.trevorism.auth.model.ForgotPasswordRequest
import com.trevorism.auth.model.Identity
import com.trevorism.auth.model.RegistrationRequest
import com.trevorism.auth.model.TokenRequest
import com.trevorism.auth.model.User
import io.micronaut.security.authentication.Authentication

interface TenantUserService {

    User registerUser(RegistrationRequest request)
    User forgotPassword(ForgotPasswordRequest forgotPasswordRequest)
    boolean activateUser(ActivationRequest activationRequest, Authentication authentication)
    boolean deactivateUser(ActivationRequest activationRequest, Authentication authentication)
    boolean validateCredentials(TokenRequest tokenRequest)
    User getCurrentUser(Authentication authentication)
    boolean changePassword(ChangePasswordRequest changePasswordRequest)
    Identity getIdentity(TokenRequest tokenRequest)
}