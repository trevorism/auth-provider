package com.trevorism.auth.service

import com.trevorism.ClasspathBasedPropertiesProvider
import com.trevorism.PropertiesProvider
import com.trevorism.auth.model.Identity
import com.trevorism.auth.model.SupportedOauth2Provider
import com.trevorism.auth.model.TokenRequest
import com.trevorism.auth.model.User
import com.trevorism.secure.Roles
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jws
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
        Map<String, String> claims = createClaimsMap(identity)
        String audienceClaim = audience ?: "trevorism.com"
        return Jwts.builder()
                .subject(identity.getIdentifer())
                .issuer("https://trevorism.com")
                .issuedAt(new Date())
                .expiration(Date.from(Instant.now().plusSeconds(FIFTEEN_MINUTES_IN_SECONDS)))
                .audience().add(audienceClaim).and()
                .claims(claims)
                .signWith(key)
                .compressWith(Jwts.ZIP.GZIP)
                .compact()

    }

    private static LinkedHashMap<String, String> createClaimsMap(Identity identity) {
        Map claims = ["role": getRoleForIdentity(identity), "dbId": identity.id, "entityType": getTypeForIdentity(identity)]
        if (identity.tenantGuid) {
            claims.put("tenant", identity.tenantGuid)
        }
        if (identity.permissions) {
            claims.put("permissions", identity.permissions)
        }
        return claims
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

    /**
     * Creates a read-only Trevorism token from the claims provided by the oauth provider
     * @param provider
     * @param claims
     * @return
     */

    @Override
    String issueTokenFromOauthProvider(SupportedOauth2Provider provider, Jws<Claims> claims) {
        Key key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(propertiesProvider.getProperty("signingKey")))
        String email = claims.payload.get("email", String)
        String name = claims.payload.get("name", String)
        String originIssuer = claims.payload.get("iss", String)
        String role = "Oauth2"
        String permissions = "R"
        Map claimsMap = ["name": name, "originIssuer": originIssuer, "email": email, "role": role, "permissions": permissions, provider: provider.name()]

        return Jwts.builder().subject(email)
                .issuer("https://trevorism.com")
                .issuedAt(new Date())
                .expiration(Date.from(Instant.now().plusSeconds(FIFTEEN_MINUTES_IN_SECONDS)))
                .audience().add("trevorism.com").and()
                .claims(claimsMap)
                .signWith(key)
                .compressWith(Jwts.ZIP.GZIP)
                .compact()
    }

    private static String getTypeForIdentity(Identity identity) {
        return identity instanceof User ? TokenRequest.USER_TYPE : TokenRequest.APP_TYPE
    }
}
