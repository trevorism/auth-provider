package com.trevorism.auth.service

import com.trevorism.auth.errors.AuthException
import com.trevorism.auth.model.Identity
import com.trevorism.auth.model.TokenRequest
import com.trevorism.auth.model.User
import com.trevorism.PropertiesProvider
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jws
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.security.Keys
import org.junit.jupiter.api.Test

import javax.crypto.SecretKey

import static org.junit.jupiter.api.Assertions.assertThrows

class AccessTokenServiceTest {

    public static final String TEST_SIGNING_KEY = "1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz"

    @Test
    void testIssueToken() {
        TokenService accessTokenService = new AccessTokenService()
        accessTokenService.propertiesProvider = [getProperty: {x -> return TEST_SIGNING_KEY }] as PropertiesProvider
        String token = accessTokenService.issueToken(new User(username: "testUsername"), "testAudience")

        assert token
        assertTokenDecodes(token)
    }

    @Test
    void testIssueTokenNullUserAudienceStillWorks() {
        TokenService accessTokenService = new AccessTokenService()
        accessTokenService.propertiesProvider = [getProperty: {x -> return TEST_SIGNING_KEY }] as PropertiesProvider
        String token = accessTokenService.issueToken(new User(), "")

        assert token
    }

    @Test
    void testIssueRefreshToken() {
        TokenService accessTokenService = new AccessTokenService()
        accessTokenService.propertiesProvider = [getProperty: {x -> return TEST_SIGNING_KEY }] as PropertiesProvider

        String token = accessTokenService.issueRefreshToken(new User(), null)
        assert token
    }

    @Test
    void testRefreshTokenAudienceIsPinned() {
        AccessTokenService accessTokenService = new AccessTokenService()
        accessTokenService.propertiesProvider = [getProperty: {x -> return TEST_SIGNING_KEY }] as PropertiesProvider

        String token = accessTokenService.issueRefreshToken(new User(username: "testUsername"), "service.trevorism.com")

        Claims claims = parseClaims(token)
        assert (claims.get("aud") as HashSet).contains(AccessTokenService.REFRESH_AUDIENCE)
        assert !(claims.get("aud") as HashSet).contains("service.trevorism.com")
        assert claims.get("targetAudience") == "service.trevorism.com"
        assert claims.get("entityType") == TokenRequest.REFRESH_TYPE
    }

    @Test
    void testRedeemRefreshTokenPreservesTargetAudience() {
        AccessTokenService accessTokenService = new AccessTokenService()
        accessTokenService.propertiesProvider = [getProperty: {x -> return TEST_SIGNING_KEY }] as PropertiesProvider
        accessTokenService.tenantUserService = [getIdentity: {TokenRequest req -> new User(username: "testUsername") }] as TenantUserService

        String refreshToken = accessTokenService.issueRefreshToken(new User(username: "testUsername"), "service.trevorism.com")
        String accessToken = accessTokenService.redeemRefreshToken(refreshToken)

        Claims claims = parseClaims(accessToken)
        assert (claims.get("aud") as HashSet).contains("service.trevorism.com")
        assert claims.get("entityType") == TokenRequest.USER_TYPE
        assert claims.get("role")
    }

    @Test
    void testRedeemRejectsNonRefreshToken() {
        AccessTokenService accessTokenService = new AccessTokenService()
        accessTokenService.propertiesProvider = [getProperty: {x -> return TEST_SIGNING_KEY }] as PropertiesProvider

        String accessToken = accessTokenService.issueToken(new User(username: "testUsername"), "service.trevorism.com")
        assertThrows(AuthException, () -> accessTokenService.redeemRefreshToken(accessToken))
    }

    @Test
    void testRedeemThrowsWhenIdentityNotFound() {
        AccessTokenService accessTokenService = new AccessTokenService()
        accessTokenService.propertiesProvider = [getProperty: {x -> return TEST_SIGNING_KEY }] as PropertiesProvider
        accessTokenService.tenantUserService = [getIdentity: {TokenRequest req -> null }] as TenantUserService

        String refreshToken = accessTokenService.issueRefreshToken(new User(username: "testUsername"), null)
        assertThrows(AuthException, () -> accessTokenService.redeemRefreshToken(refreshToken))
    }

    @Test
    void testRedeemRejectsTamperedToken() {
        AccessTokenService accessTokenService = new AccessTokenService()
        accessTokenService.propertiesProvider = [getProperty: {x -> return TEST_SIGNING_KEY }] as PropertiesProvider

        assertThrows(AuthException, () -> accessTokenService.redeemRefreshToken("not.a.validtoken"))
    }

    private static Claims parseClaims(String token) {
        SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(TEST_SIGNING_KEY))
        return Jwts.parser()
                .clockSkewSeconds(10)
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .payload
    }

    private static void assertTokenDecodes(String token) {
        SecretKey key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(TEST_SIGNING_KEY))

        Jws<Claims> decoded = Jwts.parser()
                .clockSkewSeconds(10)
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)

        assert decoded.payload.get("iss") == "https://trevorism.com"
        assert (decoded.payload.get("aud") as HashSet).contains("testAudience")
        assert decoded.payload.get("sub") == "testUsername"
    }
}
