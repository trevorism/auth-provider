package com.trevorism.auth.service

import com.trevorism.auth.bean.SecureHttpClientProvider
import com.trevorism.data.FastDatastoreRepository
import com.trevorism.data.Repository
import com.trevorism.data.model.filtering.FilterBuilder
import com.trevorism.data.model.filtering.SimpleFilter
import com.trevorism.auth.model.App
import com.trevorism.auth.model.Identity
import com.trevorism.auth.model.SaltedPassword


import java.time.Instant
import java.time.temporal.ChronoUnit

@jakarta.inject.Singleton
class DefaultAppRegistrationService implements AppRegistrationService{

    private Repository<App> repository

    DefaultAppRegistrationService(SecureHttpClientProvider provider){
        this.repository = new FastDatastoreRepository<>(App, provider.getSecureHttpClient())
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
    App registerApp(App app) {
        app.clientSecret = null
        app.clientId = UUID.randomUUID().toString()
        app.dateCreated = new Date()
        app.dateExpired = Date.from(Instant.now().plus(365, ChronoUnit.DAYS))
        app.active = true

        return repository.create(app)
    }

    @Override
    String generateClientSecret(App app) {
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
            throw new RuntimeException("Unable to generate secret: cannot find app by id")
        if(app.clientId != retrievedApp.clientId)
            throw new RuntimeException("Unable to generate secret: cannot find clientId")
        return retrievedApp
    }

    private static App setPasswordAndSalt(App app, String rawSecret) {
        SaltedPassword sp = HashUtils.createPasswordAndSalt(rawSecret)
        app.salt = sp.salt
        app.clientSecret = sp.password
        return app
    }

    @Override
    boolean validateCredentials(String identifier, String password) {
        if(!identifier || !password){
            return false
        }

        App app = getIdentity(identifier)

        if(!app || !app.clientId || !app.clientSecret || !app.salt || !app.active || HashUtils.isExpired(app.dateExpired)){
            return false
        }

        return validatePasswordsMatch(app, password)

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
}
