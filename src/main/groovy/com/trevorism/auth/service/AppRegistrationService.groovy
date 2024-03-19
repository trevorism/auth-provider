package com.trevorism.auth.service

import com.trevorism.auth.model.App

interface AppRegistrationService extends CredentialValidator {

    App registerApp(App app)
    List<App> listRegisteredApps()
    App getRegisteredApp(String id)
    App removeRegisteredApp(String id)
    String generateClientSecret(App app)
}