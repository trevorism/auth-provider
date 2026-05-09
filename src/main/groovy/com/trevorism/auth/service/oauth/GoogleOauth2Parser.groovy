package com.trevorism.auth.service.oauth

import com.trevorism.http.HttpClient
import jakarta.inject.Named

@jakarta.inject.Singleton
@Named("google")
class GoogleOauth2Parser extends Oauth2ParserBase implements Oauth2Parser {

    private static final String GOOGLE_CERT_URL = "https://www.googleapis.com/oauth2/v3/certs"
    private static final List<String> GOOGLE_ISSUERS = ["https://accounts.google.com"]
    private static final List<String> GOOGLE_CLIENT_IDS = ["20040999009-8gnongpbu2fujg8at7bvl3st1h37hpaq.apps.googleusercontent.com"]

    GoogleOauth2Parser(@Named("injectableHttpClient") HttpClient httpClient) {
        super(httpClient)
    }

    @Override
    String getCertUrl() {
        return GOOGLE_CERT_URL
    }

    @Override
    List<String> getIssuers() {
        return GOOGLE_ISSUERS
    }

    @Override
    List<String> getClientIds() {
        return GOOGLE_CLIENT_IDS
    }
}
