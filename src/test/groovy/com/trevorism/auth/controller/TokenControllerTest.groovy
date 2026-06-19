package com.trevorism.auth.controller

import com.trevorism.auth.errors.AuthException
import com.trevorism.auth.model.Identity
import com.trevorism.auth.model.InternalTokenRequest
import com.trevorism.auth.model.RedeemRequest
import com.trevorism.auth.model.TokenRequest
import com.trevorism.auth.service.TokenService
import com.trevorism.secure.Roles
import io.micronaut.security.authentication.Authentication
import org.junit.jupiter.api.Test

import static org.junit.jupiter.api.Assertions.assertThrows

class TokenControllerTest {

    private static final String FAKE_TOKEN = "eyzz.asdf.gdsfg"


    @Test
    void testBadTokenRequest() {
        TokenController tokenController = new TokenController()
        tokenController.tokenService = [getValidatedIdentity: {tr -> null as Identity}, issueToken: {u,aud -> FAKE_TOKEN}] as TokenService
        assertThrows(AuthException, () -> tokenController.createToken(new TokenRequest()))
    }

    @Test
    void testBadTokenUserRequest() {
        TokenController tokenController = new TokenController()
        tokenController.tokenService = [getValidatedIdentity: {tr -> null as Identity}, issueToken: {u,aud -> FAKE_TOKEN}] as TokenService
        assertThrows(AuthException, () -> tokenController.createToken(new TokenRequest(type: TokenRequest.USER_TYPE)))
    }

    @Test
    void testGetUserToken() {
        TokenController tokenController = new TokenController()
        tokenController.tokenService = [getValidatedIdentity: {tr -> { } as Identity}, issueToken: {u,aud -> FAKE_TOKEN}] as TokenService
        assert FAKE_TOKEN == tokenController.createToken(new TokenRequest(id:"username", password: "password", type: TokenRequest.USER_TYPE))
    }

    @Test
    void testGetAppToken() {
        TokenController tokenController = new TokenController()
        tokenController.tokenService = [getValidatedIdentity: {tr -> { } as Identity}, issueToken: {u,aud -> FAKE_TOKEN}] as TokenService
        assert FAKE_TOKEN == tokenController.createToken(new TokenRequest(id:"username", password: "password", type: TokenRequest.APP_TYPE))
    }

    @Test
    void testRedeemMissingRefreshTokenThrows() {
        TokenController tokenController = new TokenController()
        tokenController.tokenService = [redeemRefreshToken: {t, aud -> FAKE_TOKEN}] as TokenService
        assertThrows(AuthException, () -> tokenController.redeemRefreshToken(new RedeemRequest()))
    }

    @Test
    void testRedeemRefreshToken() {
        TokenController tokenController = new TokenController()
        tokenController.tokenService = [redeemRefreshToken: {t, aud -> FAKE_TOKEN}] as TokenService
        assert FAKE_TOKEN == tokenController.redeemRefreshToken(new RedeemRequest(refreshToken: "some.refresh.token"))
    }

    @Test
    void testCreateInternalToken() {
        TokenController tokenController = new TokenController()
        tokenController.tokenService = [issueInternalToken: {u,v,w -> FAKE_TOKEN}] as TokenService
        String token = tokenController.createInternalToken(new InternalTokenRequest(subject: "sub", audience: "aud", tenantId: "tenant"),
                [getRoles: { -> [Roles.ADMIN]}, getAttributes: { -> [:]}] as Authentication)
        assert FAKE_TOKEN == token
    }

}
