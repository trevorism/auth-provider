package com.trevorism.auth.controller

import com.trevorism.auth.errors.AuthException
import com.trevorism.auth.model.Identity
import com.trevorism.auth.model.InternalTokenRequest
import com.trevorism.auth.model.TokenRequest
import com.trevorism.auth.model.User
import com.trevorism.auth.service.AppRegistrationService
import com.trevorism.auth.service.TokenService
import com.trevorism.auth.service.UserService
import com.trevorism.ClaimProperties
import com.trevorism.secure.Roles
import io.micronaut.http.HttpHeaders
import io.micronaut.security.authentication.Authentication
import org.apache.hc.client5.http.HttpResponseException
import org.junit.jupiter.api.Test

import static org.junit.jupiter.api.Assertions.assertThrows

class TokenControllerTest {

    private static final String FAKE_TOKEN = "eyzz.asdf.gdsfg"


    @Test
    void testBadTokenRequest() {
        TokenController tokenController = new TokenController()
        tokenController.tokenService = [getValidatedIdentity: {tr -> null as Identity}, issueToken: {u,aud -> FAKE_TOKEN}] as TokenService
        assertThrows(AuthException, () -> tokenController.getToken(new TokenRequest()))
    }

    @Test
    void testBadTokenUserRequest() {
        TokenController tokenController = new TokenController()
        tokenController.tokenService = [getValidatedIdentity: {tr -> null as Identity}, issueToken: {u,aud -> FAKE_TOKEN}] as TokenService
        assertThrows(AuthException, () -> tokenController.getToken(new TokenRequest(type: TokenRequest.USER_TYPE)))
    }

    @Test
    void testGetUserToken() {
        TokenController tokenController = new TokenController()
        tokenController.tokenService = [getValidatedIdentity: {tr -> { } as Identity}, issueToken: {u,aud -> FAKE_TOKEN}] as TokenService
        assert FAKE_TOKEN == tokenController.getToken(new TokenRequest(id:"username", password: "password", type: TokenRequest.USER_TYPE))
    }

    @Test
    void testGetAppToken() {
        TokenController tokenController = new TokenController()
        tokenController.tokenService = [getValidatedIdentity: {tr -> { } as Identity}, issueToken: {u,aud -> FAKE_TOKEN}] as TokenService
        assert FAKE_TOKEN == tokenController.getToken(new TokenRequest(id:"username", password: "password", type: TokenRequest.APP_TYPE))
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
