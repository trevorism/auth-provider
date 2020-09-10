package com.trevorism.gcloud.webapi.service

import com.trevorism.gcloud.webapi.model.TokenRequest
import com.trevorism.gcloud.webapi.model.User
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jws
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.security.Keys
import org.junit.Test

import java.security.Key

class AccessTokenServiceTest {

    @Test
    void testIssueToken() {
        TokenService accessTokenService = new AccessTokenService()
        String token = accessTokenService.issueToken(new User(username: "testUsername"), new TokenRequest(audience: "testAudience"))

        assert token
        assertTokenDecodes(token)
    }

    @Test
    void testIssueTokenNullUserAudienceStillWorks() {
        TokenService accessTokenService = new AccessTokenService()
        String token = accessTokenService.issueToken(new User(), new TokenRequest())

        assert token
    }

    private static void assertTokenDecodes(String token) {
        Properties properties = new Properties()
        properties.load(AccessTokenService.class.getClassLoader().getResourceAsStream("secrets.properties") as InputStream)

        String signingKey = properties.get("signingKey")
        Key key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(signingKey))

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
