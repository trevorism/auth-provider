package com.trevorism.auth.service

import com.trevorism.ClaimProperties
import com.trevorism.ClaimsProvider
import com.trevorism.ClasspathBasedPropertiesProvider
import com.trevorism.PropertiesProvider
import com.trevorism.auth.model.Identity
import com.trevorism.auth.model.TokenRequest
import com.trevorism.auth.model.User
import com.trevorism.secure.Roles
import io.jsonwebtoken.CompressionCodecs
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.security.Keys

import java.security.Key
import java.time.Instant

class AccessTokenService implements TokenService {

    public static final int FIFTEEN_MINUTES_IN_SECONDS = 60 * 15
    public static final int ONE_DAY_IN_SECONDS = 60 * 60 * 24

    private PropertiesProvider propertiesProvider = new ClasspathBasedPropertiesProvider()

    @Override
    String issueToken(Identity identity, String audience) {
        Key key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(propertiesProvider.getProperty("signingKey")))

        String aud = audience ?: "trevorism.com"
        String role = getRoleForIdentity(identity)
        String type = getTypeForIdentity(identity)
        Map claims = ["role": role, "dbId": identity.id, "entityType": type]
        if (identity.tenantGuid) {
            claims.put("tenant", identity.tenantGuid)
        }

        return Jwts.builder()
                .setSubject(identity.getIdentifer())
                .setIssuer("https://trevorism.com")
                .setIssuedAt(new Date())
                .setExpiration(Date.from(Instant.now().plusSeconds(FIFTEEN_MINUTES_IN_SECONDS)))
                .setAudience(aud)
                .addClaims(claims)
                .signWith(key)
                .compressWith(CompressionCodecs.GZIP)
                .compact()

    }

    private static String getRoleForIdentity(Identity identity) {
        String role = Roles.SYSTEM
        if (identity instanceof User) {
            role = Roles.USER
            if (identity.admin) {
                role = Roles.ADMIN
            }
        }
        return role
    }

    @Override
    String issueRefreshToken(Identity identity) {
        Key key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(propertiesProvider.getProperty("signingKey")))

        String aud = "auth.trevorism.com"
        String type = getTypeForIdentity(identity)
        Map claims = ["dbId": identity.id, "entityType": type]

        return Jwts.builder()
                .setSubject(identity.getIdentifer())
                .setIssuer("https://trevorism.com")
                .setIssuedAt(new Date())
                .setExpiration(Date.from(Instant.now().plusSeconds(ONE_DAY_IN_SECONDS)))
                .setAudience(aud)
                .addClaims(claims)
                .signWith(key)
                .compressWith(CompressionCodecs.GZIP)
                .compact()
    }

    @Override
    ClaimProperties getClaimProperties(String bearerToken) {
        ClaimsProvider.getClaims(bearerToken, propertiesProvider.getProperty("signingKey"))
    }

    private static String getTypeForIdentity(Identity identity) {
        return identity instanceof User ? TokenRequest.USER_TYPE : TokenRequest.APP_TYPE
    }
}
