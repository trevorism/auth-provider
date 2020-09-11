package com.trevorism.gcloud.webapi.service

import com.trevorism.gcloud.webapi.model.Identity
import com.trevorism.gcloud.webapi.model.Roles
import com.trevorism.gcloud.webapi.model.TokenRequest
import com.trevorism.secure.PasswordProvider
import io.jsonwebtoken.CompressionCodecs
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.security.Keys

import java.security.Key
import java.time.Instant

class AccessTokenService implements TokenService{

    private PasswordProvider passwordProvider = new PasswordProvider()
    public static final int FIFTEEN_MINUTES_IN_SECONDS = 60 * 15

    @Override
    String issueToken(Identity identity, TokenRequest tokenRequest) {
        Key key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(passwordProvider.getSigningKey()))

        String aud = tokenRequest.audience ?: "trevorism.com"

        String jwsString = Jwts.builder()
                .setSubject(identity.getIdentifer())
                .setIssuer("https://trevorism.com")
                .setIssuedAt(new Date())
                .setExpiration(Instant.now().plusSeconds(FIFTEEN_MINUTES_IN_SECONDS).toDate())
                .setAudience(aud)
                .signWith(key)
                .compressWith(CompressionCodecs.GZIP)
                .compact()

        return jwsString

    }
}
