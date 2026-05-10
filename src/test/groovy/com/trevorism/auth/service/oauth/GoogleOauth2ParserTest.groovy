package com.trevorism.auth.service.oauth

import com.trevorism.http.HttpClient
import org.junit.jupiter.api.Test

import static org.junit.jupiter.api.Assertions.*

class GoogleOauth2ParserTest {

    private GoogleOauth2Parser parser = new GoogleOauth2Parser([:] as HttpClient)

    @Test
    void testGetCertUrl() {
        assert parser.getCertUrl() == "https://www.googleapis.com/oauth2/v3/certs"
    }

    @Test
    void testGetIssuer() {
        assert parser.getIssuer() == "https://accounts.google.com"
    }

    @Test
    void testGetClientId() {
        assert parser.getClientId() == "20040999009-8gnongpbu2fujg8at7bvl3st1h37hpaq.apps.googleusercontent.com"
    }
}
