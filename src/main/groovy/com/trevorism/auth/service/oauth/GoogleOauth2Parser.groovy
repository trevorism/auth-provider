package com.trevorism.auth.service.oauth

import com.trevorism.http.HttpClient
import jakarta.inject.Named

@jakarta.inject.Singleton
@Named("google")
class GoogleOauth2Parser extends Oauth2ParserBase implements Oauth2Parser {

    private static final String GOOGLE_CERT_URL = "https://www.googleapis.com/oauth2/v3/certs"
    private static final String GOOGLE_ISSUER = "https://accounts.google.com"
    private static final String GOOGLE_CLIENT_ID = "20040999009-8gnongpbu2fujg8at7bvl3st1h37hpaq.apps.googleusercontent.com"

    GoogleOauth2Parser(@Named("injectableHttpClient") HttpClient httpClient) {
        super(httpClient)
    }

    @Override
    String getCertUrl() {
        return GOOGLE_CERT_URL
    }

    @Override
    String getIssuer() {
        return GOOGLE_ISSUER
    }

    @Override
    String getClientId() {
        return GOOGLE_CLIENT_ID
    }
}
