package com.trevorism.gcloud.webapi.service

import com.trevorism.gcloud.webapi.model.User
import io.jsonwebtoken.CompressionCodecs
import io.jsonwebtoken.Jwts
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.security.Keys

import java.security.Key
import java.time.Instant

class AccessTokenService implements TokenService{

    @Override
    String issueToken(User user) {
        Properties properties = new Properties()
        properties.load(AccessTokenService.class.getClassLoader().getResourceAsStream("secrets.properties") as InputStream)

        String signingKey = properties.get("signingKey")
        Key key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(signingKey))

        String jwsString = Jwts.builder()
                .setSubject(user.username)
                .setIssuer("https://auth.trevorism.com/")
                .setIssuedAt(new Date())
                .setExpiration(Instant.now().plusSeconds(60*15).toDate())
                .setAudience("trevorism.com")
                .signWith(key)
                .compressWith(CompressionCodecs.GZIP)
                .compact()

        return jwsString

    }
}
