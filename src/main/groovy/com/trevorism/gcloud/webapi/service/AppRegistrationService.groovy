package com.trevorism.gcloud.webapi.service

import com.trevorism.gcloud.webapi.model.App

interface AppRegistrationService extends CredentialValidator {

    List<App> listRegisteredApps()
    App getRegisteredApp(String id)
    App removeRegisteredApp(String id)

    App registerApp(App app)
    String generateClientSecret(App app)
}