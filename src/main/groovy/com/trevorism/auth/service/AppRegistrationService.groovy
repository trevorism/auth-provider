package com.trevorism.auth.service

interface AppRegistrationService extends CredentialValidator {

    List<com.trevorism.auth.model.App> listRegisteredApps()
    com.trevorism.auth.model.App getRegisteredApp(String id)
    com.trevorism.auth.model.App removeRegisteredApp(String id)

    com.trevorism.auth.model.App registerApp(com.trevorism.auth.model.App app)
    String generateClientSecret(com.trevorism.auth.model.App app)
}