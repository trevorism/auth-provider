package com.trevorism.auth.service

import com.trevorism.auth.model.App

interface AppRegistrationService extends CredentialValidator {

    List<App> listRegisteredApps()
    App getRegisteredApp(String id)
    App removeRegisteredApp(String id)

    App registerApp(App app)
    String generateClientSecret(App app)
}