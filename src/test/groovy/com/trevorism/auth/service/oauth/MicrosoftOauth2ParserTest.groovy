package com.trevorism.auth.service.oauth

import com.trevorism.http.HttpClient
import org.junit.jupiter.api.Test
import static org.junit.jupiter.api.Assertions.*

class MicrosoftOauth2ParserTest {
    private MicrosoftOauth2Parser parser = new MicrosoftOauth2Parser([:] as HttpClient)

    @Test
    void testGetCertUrl() {
        assert parser.getCertUrl() == "https://login.microsoftonline.com/d77da90e-329a-41c3-b8b7-f76b8bf71b06/discovery/v2.0/keys?appid=c3ede79b-cc30-4f21-818c-45f727113b0e"
    }

    @Test
    void testGetIssuer() {
        assert parser.getIssuer() == "https://sts.windows.net/d77da90e-329a-41c3-b8b7-f76b8bf71b06/"
    }

    @Test
    void testGetClientId() {
        assert parser.getClientId() == "c3ede79b-cc30-4f21-818c-45f727113b0e"
    }
}
