package com.trevorism.auth.service

interface CredentialValidator {

    boolean validateCredentials(String identifier, String password)

    com.trevorism.auth.model.Identity getIdentity(String identifier)
}