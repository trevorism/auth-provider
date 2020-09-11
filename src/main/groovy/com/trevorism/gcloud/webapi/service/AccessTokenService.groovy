package com.trevorism.gcloud.webapi.service

import com.trevorism.gcloud.webapi.model.*
import com.trevorism.secure.PasswordProvider
import com.trevorism.secure.Roles
import io.jsonwebtoken.CompressionCodecs
import io.jsonwebtoken.JwtBuilder
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.security.Keys

import java.security.Key
import java.time.Instant

class AccessTokenService implements TokenService {

    private RoleService roleService = new DefaultUserRoleService();
    private PasswordProvider passwordProvider = new PasswordProvider()
    public static final int FIFTEEN_MINUTES_IN_SECONDS = 60 * 15

    @Override
    String issueToken(Identity identity, TokenRequest tokenRequest) {
        Key key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(passwordProvider.getSigningKey()))

        String aud = tokenRequest.audience ?: "trevorism.com"

        JwtBuilder builder = Jwts.builder()
                .setSubject(identity.getIdentifer())
                .setIssuer("https://trevorism.com")
                .setIssuedAt(new Date())
                .setExpiration(Instant.now().plusSeconds(FIFTEEN_MINUTES_IN_SECONDS).toDate())
                .setAudience(aud)

        builder = setRoleForIdentity(identity, builder)
        return builder.signWith(key).compressWith(CompressionCodecs.GZIP).compact()

    }

    private JwtBuilder setRoleForIdentity(Identity identity, JwtBuilder builder) {
        String role
        if (identity instanceof App) {
            role = Roles.TENANT_ADMIN
        } else if (identity instanceof User) {
            UserRole userRole = roleService.findByUserId(identity.id)
            role = userRole?.role
        }

        if (role) {
            builder.addClaims(["role": role])
        }
        return builder
    }
}
