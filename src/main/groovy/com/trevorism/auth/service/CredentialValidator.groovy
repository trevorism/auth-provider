package com.trevorism.auth.service

import com.trevorism.auth.model.Identity
import com.trevorism.auth.model.TokenRequest

interface CredentialValidator {

    boolean validateCredentials(TokenRequest tokenRequest)

    Identity getIdentity(String identifier)
}