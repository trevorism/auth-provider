package com.trevorism.auth.service.oauth

import com.trevorism.http.HttpClient
import org.junit.jupiter.api.Test
import static org.junit.jupiter.api.Assertions.*

class MicrosoftOauth2ParserTest {
    private MicrosoftOauth2Parser parser = new MicrosoftOauth2Parser([:] as HttpClient)

    @Test
    void testGetCertUrl() {
        assert parser.getCertUrl() == "https://login.microsoftonline.com/d77da90e-329a-41c3-b8b7-f76b8bf71b06/discovery/v2.0/keys"
    }

    @Test
    void testGetIssuers() {
        assert parser.getIssuers() == [
                "https://sts.windows.net/d77da90e-329a-41c3-b8b7-f76b8bf71b06/",
                "https://login.microsoftonline.com/d77da90e-329a-41c3-b8b7-f76b8bf71b06/v2.0"
        ]
    }

    @Test
    void testGetClientIds() {
        assert parser.getClientIds() == [
                "c3ede79b-cc30-4f21-818c-45f727113b0e",
                "6a213614-458e-4167-a7d7-7a0b099a6e5a"
        ]
    }
}
