package com.trevorism.auth.controller

import com.trevorism.auth.errors.AuthException
import com.trevorism.auth.model.Oauth2Tokens
import com.trevorism.auth.service.AccessTokenService
import org.junit.jupiter.api.Test
import static org.junit.jupiter.api.Assertions.assertThrows

class MicrosoftControllerTest {
    @Test
    void testCreateToken(){
        MicrosoftController controller = new MicrosoftController()
        controller.tokenService = new AccessTokenService()
        String idToken = "ey.."
        assertThrows(AuthException, () -> controller.createToken(new Oauth2Tokens(id_token: idToken)))

    }
}
