package com.trevorism.util

import com.google.gson.Gson
import com.trevorism.auth.model.TokenRequest
import com.trevorism.http.HttpClient
import com.trevorism.https.SecureHttpClient
import com.trevorism.https.SecureHttpClientBase
import com.trevorism.https.token.ObtainTokenStrategy

class AdminUserSecureHttpClient extends SecureHttpClientBase implements SecureHttpClient {

    AdminUserSecureHttpClient(HttpClient httpClient, String password, String tenantGuid, String audience) {
        super(httpClient, new ObtainTokenFromAdminUser(password, tenantGuid, audience))
    }

    static class ObtainTokenFromAdminUser implements ObtainTokenStrategy {
        private String audience
        private HttpClient httpClient
        private Gson gson = new Gson()
        private String tenantGuid
        private String password
        private String token

        ObtainTokenFromAdminUser(String password, String tenantGuid, String audience) {
            this.audience = audience
            this.tenantGuid = tenantGuid
            this.password = password
        }

        @Override
        String getToken() {
            if (token)
                return token

            TokenRequest tokenRequest = new TokenRequest()
            tokenRequest.id = "auth_tests_admin_user"
            tokenRequest.password = password
            tokenRequest.tenantGuid = tenantGuid
            tokenRequest.audience = audience
            tokenRequest.type = TokenRequest.USER_TYPE
            token = httpClient.post("https://auth.trevorism.com/token", gson.toJson(tokenRequest))
            return token
        }

        @Override
        void setHttpClient(HttpClient httpClient) {
            this.httpClient = httpClient
        }
    }
}


