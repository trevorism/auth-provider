package com.trevorism.auth.service

import com.trevorism.auth.bean.TenantTokenSecureHttpClientProvider
import com.trevorism.auth.errors.AuthException
import com.trevorism.auth.model.TokenRequest
import com.trevorism.data.FastDatastoreRepository
import com.trevorism.data.Repository
import com.trevorism.data.model.filtering.FilterBuilder
import com.trevorism.data.model.filtering.SimpleFilter
import com.trevorism.auth.model.App
import com.trevorism.auth.model.Identity
import com.trevorism.auth.model.SaltedPassword
import com.trevorism.https.SecureHttpClient
import com.trevorism.secure.Roles
import io.micronaut.runtime.http.scope.RequestScope
import io.micronaut.security.authentication.Authentication
import jakarta.inject.Inject
import jakarta.inject.Named
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.time.Instant
import java.time.temporal.ChronoUnit

@RequestScope
class DefaultAppRegistrationService implements AppRegistrationService{

    private static final Logger log = LoggerFactory.getLogger(DefaultAppRegistrationService)
    private Repository<App> repository

    @Inject
    TenantTokenSecureHttpClientProvider generateTokenSecureHttpClientProvider

    DefaultAppRegistrationService(@Named("passThruSecureHttpClient") SecureHttpClient httpClient){
        this.repository = new FastDatastoreRepository<>(App, httpClient)
    }

    @Override
    List<App> listRegisteredApps() {
        repository.list().collect{
            cleanApp(it)
        }
    }

    @Override
    App getRegisteredApp(String id) {
        App app = repository.get(id)
        return cleanApp(app)
    }

    @Override
    App removeRegisteredApp(String id) {
        App app = repository.delete(id)
        return cleanApp(app)
    }

    @Override
    App registerApp(App app, Authentication authentication) {
        validateAppRegistration(authentication, app)
        app.clientSecret = null
        app.clientId = UUID.randomUUID().toString()
        app.dateCreated = new Date()
        app.dateExpired = Date.from(Instant.now().plus(365, ChronoUnit.DAYS))
        app.active = true

        return repository.create(app)
    }

    @Override
    String generateClientSecret(App app, Authentication authentication) {
        validateAppRegistration(authentication, app)
        app = validateApp(app)
        String rawSecret = HashUtils.generateRawSecret()
        app = setPasswordAndSalt(app, rawSecret)
        app.dateExpired = Date.from(Instant.now().plus(365, ChronoUnit.DAYS))
        repository.update(app.id, app)
        return rawSecret
    }

    private static App cleanApp(App app) {
        app?.clientSecret = null
        app?.salt = null
        return app
    }

    App validateApp(App app) {
        App retrievedApp = repository.get(app.id)
        if(!retrievedApp)
            throw new AuthException("Unable to generate secret: cannot find app by id")
        if(app.clientId != retrievedApp.clientId)
            throw new AuthException("Unable to generate secret: cannot find clientId")
        return retrievedApp
    }

    private static App setPasswordAndSalt(App app, String rawSecret) {
        SaltedPassword sp = HashUtils.createPasswordAndSalt(rawSecret)
        app.salt = sp.salt
        app.clientSecret = sp.password
        return app
    }

    @Override
    boolean validateCredentials(TokenRequest tokenRequest) {
        String identifier = tokenRequest.id
        String password = tokenRequest.password

        if(!identifier || !password){
            return false
        }

        App app = getAppFromRequest(tokenRequest, identifier)

        if(!app || !app.clientId || !app.clientSecret || !app.salt || !app.active || HashUtils.isExpired(app.dateExpired)){
            return false
        }

        return validatePasswordsMatch(app, password)

    }

    private App getAppFromRequest(TokenRequest tokenRequest, String identifier) {
        this.repository = new FastDatastoreRepository<>(App, generateTokenSecureHttpClientProvider.getSecureHttpClient(tokenRequest.tenantGuid, tokenRequest.audience))
        App app = getIdentity(identifier) as App
        return app
    }

    @Override
    Identity getIdentity(String identifier) {
        def list = repository.filter(new FilterBuilder().addFilter(new SimpleFilter("clientId", "=", identifier)).build())
        if(!list) {
            return null
        }
        return list[0]
    }

    private static boolean validatePasswordsMatch(App app, String password) {
        SaltedPassword sp = new SaltedPassword(app.salt, app.clientSecret)
        return HashUtils.validatePasswordsMatch(sp, password)

    }

    static void validateAppRegistration(Authentication authentication, App app) {
        String role = authentication.getRoles().first().toString()
        if (role != Roles.ADMIN && role != Roles.TENANT_ADMIN) {
            if (role == Roles.SYSTEM)
                throw new AuthException("Apps cannot register other apps, only administrator users may do this.")
            throw new AuthException("User is not authorized to work with apps")
        }
        String tenant = authentication.getAttributes().get("tenant")
        if (tenant && tenant != app.tenantGuid) {
            throw new AuthException("Tenant Admins may only work with apps for their tenant")
        }

    }
}
