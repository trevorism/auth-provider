package com.trevorism.gcloud.webapi.service

import com.trevorism.gcloud.webapi.model.Identity
import com.trevorism.gcloud.webapi.model.TokenRequest
import com.trevorism.gcloud.webapi.model.User
import com.trevorism.secure.ClaimProperties
import com.trevorism.secure.ClaimsProvider
import com.trevorism.secure.ClasspathBasedPropertiesProvider
import com.trevorism.secure.PropertiesProvider
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

    private PropertiesProvider propertiesProvider
    private final String signingKey

    AccessTokenService(){
        propertiesProvider = new ClasspathBasedPropertiesProvider()
        this.signingKey = propertiesProvider.getProperty("signingKey")
    }

    @Override
    String issueToken(Identity identity, String audience) {
        Key key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(signingKey))

        String aud = audience ?: "trevorism.com"
        String role = getRoleForIdentity(identity)
        String type = getTypeForIdentity(identity)
        Map claims = ["role": role, "dbId": identity.id, "entityType": type]

        return Jwts.builder()
                .setSubject(identity.getIdentifer())
                .setIssuer("https://trevorism.com")
                .setIssuedAt(new Date())
                .setExpiration(Instant.now().plusSeconds(FIFTEEN_MINUTES_IN_SECONDS).toDate())
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
        Key key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(signingKey))

        String aud = "auth.trevorism.com"
        String type = getTypeForIdentity(identity)
        Map claims = ["dbId": identity.id, "entityType": type]

        return Jwts.builder()
                .setSubject(identity.getIdentifer())
                .setIssuer("https://trevorism.com")
                .setIssuedAt(new Date())
                .setExpiration(Instant.now().plusSeconds(ONE_DAY_IN_SECONDS).toDate())
                .setAudience(aud)
                .addClaims(claims)
                .signWith(key)
                .compressWith(CompressionCodecs.GZIP)
                .compact()
    }

    @Override
    ClaimProperties getClaimProperties(String bearerToken) {
        ClaimsProvider.getClaims(bearerToken, signingKey)
    }

    private static String getTypeForIdentity(Identity identity) {
        return identity instanceof User ? TokenRequest.USER_TYPE : TokenRequest.APP_TYPE
    }
}
