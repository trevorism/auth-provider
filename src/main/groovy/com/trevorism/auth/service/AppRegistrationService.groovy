package com.trevorism.auth.service

import com.trevorism.auth.model.App
import io.micronaut.security.authentication.Authentication

interface AppRegistrationService extends CredentialValidator {

    App registerApp(App app, Authentication authentication)
    List<App> listRegisteredApps()
    App getRegisteredApp(String id)
    App removeRegisteredApp(String id)
    String generateClientSecret(App app, Authentication authentication)
}