package com.trevorism.auth.service.oauth

import com.trevorism.http.HttpClient
import jakarta.inject.Named

@jakarta.inject.Singleton
@Named("microsoft")
class MicrosoftOauth2Parser extends Oauth2ParserBase implements Oauth2Parser {

    private static final String TENANT_ID = "d77da90e-329a-41c3-b8b7-f76b8bf71b06"
    private static final String PRIMARY_CLIENT_ID = "c3ede79b-cc30-4f21-818c-45f727113b0e"
    private static final String SECONDARY_CLIENT_ID = "6a213614-458e-4167-a7d7-7a0b099a6e5a"
    private static final String CERT_URL = "https://login.microsoftonline.com/${TENANT_ID}/discovery/v2.0/keys"
    private static final List<String> ISSUERS = [
            "https://sts.windows.net/${TENANT_ID}/",
            "https://login.microsoftonline.com/${TENANT_ID}/v2.0"
    ]
    private static final List<String> CLIENT_IDS = [PRIMARY_CLIENT_ID, SECONDARY_CLIENT_ID]

    MicrosoftOauth2Parser(@Named("injectableHttpClient") HttpClient httpClient) {
        super(httpClient)
    }

    @Override
    String getCertUrl() {
        return CERT_URL
    }

    @Override
    List<String> getIssuers() {
        return ISSUERS
    }

    @Override
    List<String> getClientIds() {
        return CLIENT_IDS
    }
}
