package com.trevorism.auth.service.oauth

import com.trevorism.auth.errors.AuthException
import com.trevorism.auth.model.Oauth2Tokens
import com.trevorism.http.HttpClient
import org.junit.jupiter.api.Test
import static org.junit.jupiter.api.Assertions.assertThrows

class Oauth2ParserBaseTest {


    @Test
    void testParse() {
        TestOauth2ParserBase parser = new TestOauth2ParserBase([get : {url -> "{ \"keys\":[]}"}] as HttpClient)
        assertThrows(AuthException, () -> parser.parse(new Oauth2Tokens([idToken:"eyJ6aXAiOiJHWklQI.fake.token"])))
    }
}

class TestOauth2ParserBase extends Oauth2ParserBase{

    TestOauth2ParserBase(HttpClient httpClient) {
        super(httpClient)
    }

    @Override
    String getCertUrl() {
        return null
    }

    @Override
    String getIssuer() {
        return null
    }

    @Override
    String getClientId() {
        return null
    }
}
