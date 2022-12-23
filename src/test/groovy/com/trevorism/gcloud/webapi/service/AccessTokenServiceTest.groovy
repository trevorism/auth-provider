package com.trevorism.gcloud.webapi.service

import com.trevorism.gcloud.webapi.model.User
import com.trevorism.secure.ClasspathBasedPropertiesProvider
import com.trevorism.secure.PropertiesProvider
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jws
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.security.Keys
import org.junit.Test

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
        Key key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(TEST_SIGNING_KEY))

        Jws<Claims> decoded = Jwts.parserBuilder()
                .setAllowedClockSkewSeconds(10)
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)

        assert decoded.body.get("iss") == "https://trevorism.com"
        assert decoded.body.get("aud") == "testAudience"
        assert decoded.body.get("sub") == "testUsername"
    }
}
