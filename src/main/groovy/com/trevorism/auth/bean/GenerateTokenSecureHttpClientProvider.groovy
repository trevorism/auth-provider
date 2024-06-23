package com.trevorism.auth.bean

import com.trevorism.auth.model.App
import com.trevorism.auth.service.AccessTokenService
import com.trevorism.auth.service.TokenService
import com.trevorism.http.HttpClient
import com.trevorism.http.JsonHttpClient
import com.trevorism.https.SecureHttpClient
import com.trevorism.https.SecureHttpClientBase
import com.trevorism.https.token.ObtainTokenFromAuthServiceFromPropertiesFile
import com.trevorism.https.token.ObtainTokenStrategy

import java.time.Instant
import java.time.temporal.ChronoUnit

@jakarta.inject.Singleton
class GenerateTokenSecureHttpClientProvider implements TenantTokenSecureHttpClientProvider {

    private HttpClient singletonClient = new JsonHttpClient()

    @Override
    SecureHttpClient getSecureHttpClient(String tenantId, String audience) {
        return new GenerateTokenSecureHttpClient(singletonClient, tenantId, audience)
    }
}

class GenerateTokenSecureHttpClient extends SecureHttpClientBase {

    GenerateTokenSecureHttpClient(HttpClient singletonClient, String tenantId, String audience) {
        super(singletonClient, new GenerateTokenStrategy(tenantId, audience))
    }
}

class GenerateTokenStrategy extends ObtainTokenFromAuthServiceFromPropertiesFile implements ObtainTokenStrategy {

    private final String tenantId
    private final String audience

    GenerateTokenStrategy(String tenantId, String audience) {
        this.tenantId = tenantId
        this.audience = audience
    }

    @Override
    String getToken() {
        TokenService accessTokenService = new AccessTokenService()
        App app = new App()
        app.id = "5734899076038656"
        app.active = true
        app.clientId = getClientId()
        app.clientSecret = getClientSecret()
        app.dateExpired = Date.from(Instant.now().plus(1, ChronoUnit.HOURS))
        app.tenantGuid = tenantId
        accessTokenService.issueToken(app, audience)
    }

    @Override
    void setHttpClient(HttpClient httpClient) {
        //Do nothing
    }
}