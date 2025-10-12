package com.trevorism.auth.controller

import com.trevorism.auth.model.Oauth2Tokens
import com.trevorism.auth.service.TokenService
import com.trevorism.auth.service.oauth.Oauth2Parser
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jws
import org.junit.jupiter.api.Test

class MicrosoftControllerTest {

    @Test
    void testCreateToken(){
        String microsoftIdToken = "ey.microsoft.token"
        String fakeTrevorismToken = "ey.trevorism.token"

        MicrosoftController controller = new MicrosoftController()
        controller.oauth2Parser = [parse: {tokens -> [:] as Jws<Claims> } ] as Oauth2Parser
        controller.tokenService = [issueTokenFromOauthProvider: {provider, claims, tenantId -> fakeTrevorismToken}] as TokenService
        assert fakeTrevorismToken == controller.createToken(new Oauth2Tokens(idToken: microsoftIdToken))
    }

    @Test
    void testFetchClaims(){
        String microsoftIdToken = "ey.microsoft.token"
        MicrosoftController controller = new MicrosoftController()
        controller.oauth2Parser = [parse: {tokens -> [getPayload: { -> [iss:"unittest"]}] as Jws<Claims> } ] as Oauth2Parser
        def claims = controller.fetchClaims(new Oauth2Tokens(idToken: microsoftIdToken))
        assert claims.iss == "unittest"

    }
}
