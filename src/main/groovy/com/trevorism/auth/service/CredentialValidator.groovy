package com.trevorism.auth.service

import com.trevorism.auth.model.Identity

interface CredentialValidator {

    boolean validateCredentials(String identifier, String password)

    Identity getIdentity(String identifier)
}