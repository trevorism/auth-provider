package com.trevorism.auth.controller

import com.trevorism.auth.errors.AuthException
import com.trevorism.auth.model.HandoffRedeemRequest
import com.trevorism.auth.model.HandoffRequest
import com.trevorism.auth.model.HandoffResponse
import com.trevorism.auth.model.HandoffTokens
import com.trevorism.auth.model.Identity
import com.trevorism.auth.model.InternalTokenRequest
import com.trevorism.auth.model.RedeemRequest
import com.trevorism.auth.model.TokenRequest
import com.trevorism.auth.service.HandoffService
import com.trevorism.auth.service.RedirectUriPolicy
import com.trevorism.auth.service.TokenService
import io.micronaut.http.HttpRequest
import io.micronaut.http.cookie.Cookie
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
        tokenController.tokenService = [redeemRefreshToken: {t -> FAKE_TOKEN}] as TokenService
        assertThrows(AuthException, () -> tokenController.redeemRefreshToken(new RedeemRequest()))
    }

    @Test
    void testRedeemRefreshToken() {
        TokenController tokenController = new TokenController()
        tokenController.tokenService = [redeemRefreshToken: {t -> FAKE_TOKEN}] as TokenService
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

    @Test
    void testCreateHandoffCodeUsesBearerToken() {
        TokenController tokenController = new TokenController()
        Map captured = [:]
        tokenController.handoffService = [createCode: { auth, access, refresh, uri -> captured << [access: access, refresh: refresh, uri: uri]; new HandoffResponse(code: "1.abc", expiresInSeconds: 60) }] as HandoffService
        HttpRequest<?> request = HttpRequest.POST("/token/handoff", "{}").header("Authorization", "Bearer " + FAKE_TOKEN)

        HandoffResponse response = tokenController.createHandoffCode(new HandoffRequest(redirectUri: "https://a.trevorism.com/api/auth/callback", refreshToken: "r.t"), fakeAuthentication(), request)

        assert response.code == "1.abc"
        assert captured.access == FAKE_TOKEN
        assert captured.refresh == "r.t"
        assert captured.uri == "https://a.trevorism.com/api/auth/callback"
    }

    @Test
    void testCreateHandoffCodeFallsBackToSessionCookie() {
        TokenController tokenController = new TokenController()
        String seen = null
        tokenController.handoffService = [createCode: { auth, access, refresh, uri -> seen = access; new HandoffResponse(code: "1.abc", expiresInSeconds: 60) }] as HandoffService
        HttpRequest<?> request = HttpRequest.POST("/token/handoff", "{}").cookie(Cookie.of("session", FAKE_TOKEN))

        tokenController.createHandoffCode(new HandoffRequest(redirectUri: "https://a.trevorism.com/api/auth/callback"), fakeAuthentication(), request)
        assert seen == FAKE_TOKEN
    }

    @Test
    void testExtractCallerTokenIsNullWithoutCredentials() {
        assert TokenController.extractCallerToken(HttpRequest.POST("/token/handoff", "{}")) == null
        assert TokenController.extractCallerToken(HttpRequest.POST("/token/handoff", "{}").header("Authorization", "Basic abc")) == null
    }

    @Test
    void testRedeemHandoffCode() {
        TokenController tokenController = new TokenController()
        tokenController.handoffService = [redeemCode: { code, uri -> new HandoffTokens(accessToken: FAKE_TOKEN, refreshToken: "r.t") }] as HandoffService
        HandoffTokens tokens = tokenController.redeemHandoffCode(new HandoffRedeemRequest(code: "1.abc", redirectUri: "https://a.trevorism.com/api/auth/callback"))
        assert tokens.accessToken == FAKE_TOKEN
        assert tokens.refreshToken == "r.t"
    }

    @Test
    void testRedeemHandoffCodeMissingCodeThrows() {
        TokenController tokenController = new TokenController()
        tokenController.handoffService = [redeemCode: { code, uri -> new HandoffTokens() }] as HandoffService
        assertThrows(AuthException, () -> tokenController.redeemHandoffCode(new HandoffRedeemRequest(redirectUri: "https://a.trevorism.com/api/auth/callback")))
        assertThrows(AuthException, () -> tokenController.redeemHandoffCode(null))
    }

    @Test
    void testIsRedirectAllowed() {
        TokenController tokenController = new TokenController()
        tokenController.redirectUriPolicy = [isAllowed: { String uri -> uri.startsWith("https://ok") }] as RedirectUriPolicy
        assert tokenController.isRedirectAllowed("https://ok.trevorism.com/api/auth/callback").allowed
        assert !tokenController.isRedirectAllowed("https://nope.example.org/api/auth/callback").allowed
    }

    private static Authentication fakeAuthentication() {
        return [getName: { -> "tester" }, getRoles: { -> [Roles.USER] }, getAttributes: { -> [:] }] as Authentication
    }

}
