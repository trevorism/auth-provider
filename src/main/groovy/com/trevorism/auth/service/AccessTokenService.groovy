package com.trevorism.auth.service

import com.trevorism.ClaimProperties
import com.trevorism.ClaimsProvider
import com.trevorism.ClasspathBasedPropertiesProvider
import com.trevorism.PropertiesProvider
import com.trevorism.auth.model.Identity
import com.trevorism.auth.model.TokenRequest
import com.trevorism.auth.model.User
import com.trevorism.secure.Roles
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.security.Keys
import jakarta.inject.Inject

import java.security.Key
import java.time.Instant

@jakarta.inject.Singleton
class AccessTokenService implements TokenService {

    public static final int FIFTEEN_MINUTES_IN_SECONDS = 60 * 15
    public static final int ONE_DAY_IN_SECONDS = 60 * 60 * 24
    public static final int TWO_HOURS_IN_SECONDS = 60 * 60 * 2

    @Inject
    private TenantUserService tenantUserService
    @Inject
    private AppRegistrationService appRegistrationService

    private PropertiesProvider propertiesProvider = new ClasspathBasedPropertiesProvider()

    @Override
    Identity getValidatedIdentity(TokenRequest tokenRequest) {
        Identity identity = null
        if (tokenRequest.type == TokenRequest.USER_TYPE) {
            if(tenantUserService.validateCredentials(tokenRequest)) {
                identity = tenantUserService.getIdentity(tokenRequest)
            }
        }
        else{
            if(appRegistrationService.validateCredentials(tokenRequest)) {
                identity = appRegistrationService.getIdentity(tokenRequest.getId())
            }
        }
        return identity
    }

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
                .subject(identity.getIdentifer())
                .issuer("https://trevorism.com")
                .issuedAt(new Date())
                .expiration(Date.from(Instant.now().plusSeconds(FIFTEEN_MINUTES_IN_SECONDS)))
                .audience().add(aud).and()
                .claims(claims)
                .signWith(key)
                .compressWith(Jwts.ZIP.GZIP)
                .compact()

    }

    private static String getRoleForIdentity(Identity identity) {
        String role = Roles.SYSTEM
        if (identity instanceof User) {
            role = Roles.USER
            if (identity.admin) {
                if(identity.getTenantGuid()){
                    role = Roles.TENANT_ADMIN
                }
                else{
                    role = Roles.ADMIN
                }
            }

        }
        return role
    }

    @Override
    String issueRefreshToken(Identity identity) {
        Key key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(propertiesProvider.getProperty("signingKey")))

        String aud = "auth.trevorism.com"
        String type = getTypeForIdentity(identity)
        Map<String,?> claims = ["dbId": identity.id, "entityType": type]
        if (identity.tenantGuid) {
            claims.put("tenant", identity.tenantGuid)
        }

        return Jwts.builder()
                .subject(identity.getIdentifer())
                .issuer("https://trevorism.com")
                .issuedAt(new Date())
                .expiration(Date.from(Instant.now().plusSeconds(ONE_DAY_IN_SECONDS)))
                .audience().add(aud).and()
                .claims(claims)
                .signWith(key)
                .compressWith(Jwts.ZIP.GZIP)
                .compact()
    }

    @Override
    ClaimProperties getClaimProperties(String bearerToken) {
        ClaimsProvider.getClaims(bearerToken, propertiesProvider.getProperty("signingKey"))
    }

    @Override
    String issueInternalToken(Identity identity, String audience, String tenantId) {
        Key key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(propertiesProvider.getProperty("signingKey")))

        String aud = audience ?: "trevorism.com"
        String type = getTypeForIdentity(identity)
        Map claims = ["role": Roles.INTERNAL, "dbId": identity.id, "entityType": type]
        if (tenantId) {
            claims.put("tenant", tenantId)
        }

        return Jwts.builder()
                .subject(identity.getIdentifer())
                .issuer("https://trevorism.com")
                .issuedAt(new Date())
                .expiration(Date.from(Instant.now().plusSeconds(TWO_HOURS_IN_SECONDS)))
                .audience().add(aud).and()
                .claims(claims)
                .signWith(key)
                .compressWith(Jwts.ZIP.GZIP)
                .compact()
    }

    private static String getTypeForIdentity(Identity identity) {
        return identity instanceof User ? TokenRequest.USER_TYPE : TokenRequest.APP_TYPE
    }
}
