package com.trevorism.auth.controller

import com.trevorism.auth.model.Identity
import com.trevorism.auth.model.InternalTokenRequest
import com.trevorism.auth.model.TokenRequest
import com.trevorism.auth.model.User
import com.trevorism.auth.service.AccessTokenService
import com.trevorism.auth.service.AppRegistrationService
import com.trevorism.auth.service.TokenService
import com.trevorism.auth.service.UserCredentialService
import com.trevorism.ClaimProperties
import io.micronaut.http.HttpHeaders
import org.apache.hc.client5.http.HttpResponseException
import org.junit.jupiter.api.Test

import java.time.Instant

import static org.junit.jupiter.api.Assertions.assertThrows

class TokenControllerTest {

    private static final String FAKE_TOKEN = "eyzz.asdf.gdsfg"

    @Test
    void testGetBearerToken() {
        String token = TokenController.getBearerToken(createHeaders())
        assert "eyzz.asdf.gdsfg" == token
    }

    @Test
    void testRegenerateToken() {
        TokenController tokenController = new TokenController()
        Identity identity = new User()
        tokenController.userCredentialService = [getIdentity:{ sub ->
            identity.username = sub
            return identity
        }] as UserCredentialService
        tokenController.tokenService = [issueToken: {id, aud -> FAKE_TOKEN}, getClaimProperties: {str -> new ClaimProperties()}] as TokenService

        assert FAKE_TOKEN == tokenController.regenerateToken(createHeaders())
    }

    @Test
    void testBadTokenRequest() {
        TokenController tokenController = new TokenController()
        tokenController.appRegistrationService = [validateCredentials: {u,p -> false}, getIdentity: {new User(username: "test")}] as AppRegistrationService
        tokenController.tokenService = [issueToken: {u,aud -> FAKE_TOKEN}] as TokenService
        assertThrows(HttpResponseException, () -> tokenController.token(new TokenRequest()))
    }

    @Test
    void testBadTokenUserRequest() {
        TokenController tokenController = new TokenController()
        tokenController.userCredentialService = [validateCredentials: {u,p -> false}, getIdentity: {new User(username: "test")}] as UserCredentialService
        tokenController.tokenService = [issueToken: {u,aud -> FAKE_TOKEN}] as TokenService
        assertThrows(HttpResponseException, () -> tokenController.token(new TokenRequest(type: TokenRequest.USER_TYPE)))
    }

    @Test
    void testGetUserToken() {
        TokenController tokenController = new TokenController()
        tokenController.userCredentialService = [validateCredentials: {u,p -> true}, getIdentity: {new User(username: "test")}] as UserCredentialService
        tokenController.tokenService = [issueToken: {u,aud -> FAKE_TOKEN}] as TokenService
        assert FAKE_TOKEN == tokenController.token(new TokenRequest(id:"username", password: "password", type: TokenRequest.USER_TYPE))
    }

    @Test
    void testGetAppToken() {
        TokenController tokenController = new TokenController()
        tokenController.appRegistrationService = [validateCredentials: {u,p -> true}, getIdentity: {new User(username: "test")}] as AppRegistrationService
        tokenController.tokenService = [issueToken: {u,aud -> FAKE_TOKEN}] as TokenService
        assert FAKE_TOKEN == tokenController.token(new TokenRequest(id:"username", password: "password", type: TokenRequest.APP_TYPE))
    }

    @Test
    void testCreateInternalToken() {
        TokenController tokenController = new TokenController()
        tokenController.tokenService = [issueInternalToken: {u -> FAKE_TOKEN}] as TokenService
        String token = tokenController.createInternalToken(new InternalTokenRequest(subject: "sub", audience: "aud", expiration: Date.from(Instant.now().plusMillis(5000)), tenantId: "tenant"))
        assert FAKE_TOKEN == token
    }

    private HttpHeaders createHeaders() {
        def headers = ["getValue": { str -> "bearer ${FAKE_TOKEN}".toString() }] as HttpHeaders
        return headers
    }
}
