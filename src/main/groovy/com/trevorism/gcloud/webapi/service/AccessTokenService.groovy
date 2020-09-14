package com.trevorism.gcloud.webapi.service


import com.trevorism.gcloud.webapi.model.Identity
import com.trevorism.gcloud.webapi.model.TokenRequest
import com.trevorism.gcloud.webapi.model.User
import com.trevorism.secure.PasswordProvider
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

    @Override
    String issueToken(Identity identity, String audience) {
        Key key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(PasswordProvider.getInstance().getSigningKey()))

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
        Key key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(PasswordProvider.getInstance().getSigningKey()))

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

    private static String getTypeForIdentity(Identity identity) {
        return identity instanceof User ? TokenRequest.USER_TYPE : TokenRequest.APP_TYPE
    }
}
