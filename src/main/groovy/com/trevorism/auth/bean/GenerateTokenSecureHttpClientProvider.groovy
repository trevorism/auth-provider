package com.trevorism.auth.bean

import com.trevorism.auth.model.App
import com.trevorism.auth.service.AccessTokenService
import com.trevorism.auth.service.TokenService
import com.trevorism.http.HttpClient
import com.trevorism.https.SecureHttpClient
import com.trevorism.https.SecureHttpClientBase
import com.trevorism.https.token.ObtainTokenFromAuthServiceFromPropertiesFile
import com.trevorism.https.token.ObtainTokenStrategy

import java.time.Instant
import java.time.temporal.ChronoUnit

class GenerateTokenSecureHttpClientProvider implements SecureHttpClientProvider {

    private String tenantId
    private String audience

    GenerateTokenSecureHttpClientProvider(String tenantId, String audience) {
        this.tenantId = tenantId
        this.audience = audience
    }

    @Override
    SecureHttpClient getSecureHttpClient() {
        return new GenerateTokenSecureHttpClient(new GenerateTokenStrategy())
    }


    class GenerateTokenSecureHttpClient extends SecureHttpClientBase {
        GenerateTokenSecureHttpClient(ObtainTokenStrategy strategy) {
            super(strategy)
        }
    }

    class GenerateTokenStrategy extends ObtainTokenFromAuthServiceFromPropertiesFile {

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
        }
    }
}
