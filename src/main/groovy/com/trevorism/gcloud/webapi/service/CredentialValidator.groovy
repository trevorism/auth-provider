package com.trevorism.gcloud.webapi.service

import com.trevorism.gcloud.webapi.model.Identity

interface CredentialValidator {

    boolean validateCredentials(String identifier, String password)

    Identity getIdentity(String identifier)
}