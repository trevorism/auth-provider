package com.trevorism.auth.service

import com.trevorism.auth.model.User
import com.trevorism.PropertiesProvider
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jws
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.security.Keys
import org.junit.jupiter.api.Test

import javax.crypto.SecretKey
import java.security.Key

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

        String token = accessTokenService.issueRefreshToken(new User())
        assert token
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
