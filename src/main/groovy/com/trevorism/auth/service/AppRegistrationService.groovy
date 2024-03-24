package com.trevorism.auth.service

import com.trevorism.auth.model.App
import com.trevorism.auth.model.Identity
import com.trevorism.auth.model.TokenRequest
import io.micronaut.security.authentication.Authentication

interface AppRegistrationService {

    App registerApp(App app, Authentication authentication)
    List<App> listRegisteredApps()
    App getRegisteredApp(String id)
    App removeRegisteredApp(String id)
    String generateClientSecret(App app, Authentication authentication)
    boolean validateCredentials(TokenRequest tokenRequest)
    Identity getIdentity(String identifier)

}