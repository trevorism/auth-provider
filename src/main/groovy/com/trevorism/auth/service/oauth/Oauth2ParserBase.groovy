package com.trevorism.auth.service.oauth

import com.trevorism.auth.errors.AuthException
import com.trevorism.auth.model.Oauth2Tokens
import com.trevorism.http.HttpClient
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jws
import io.jsonwebtoken.Jwts
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import tools.jackson.databind.ObjectMapper

import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.RSAPublicKeySpec

abstract class Oauth2ParserBase implements Oauth2Parser {

    private static final Logger log = LoggerFactory.getLogger(Oauth2ParserBase)

    private ObjectMapper objectMapper = new ObjectMapper()
    private Base64.Decoder decoder = Base64.getUrlDecoder()

    private HttpClient httpClient

    Oauth2ParserBase(HttpClient httpClient) {
        this.httpClient = httpClient
    }

    abstract String getCertUrl()

    abstract String getIssuer()

    abstract String getClientId()

    Jws<Claims> parse(Oauth2Tokens tokens) {
        try {
            String url = getCertUrl()
            String kid = getKid(tokens.idToken)

            def jwksResponse = httpClient.get(url)
            PublicKey publicKey = getPublicKeyFromJwks(jwksResponse, kid)

            Jws<Claims> claims = Jwts.parser()
                    .verifyWith(publicKey)
                    .requireIssuer(getIssuer())
                    .requireAudience(getClientId())
                    .clockSkewSeconds(20)
                    .build().parseSignedClaims(tokens.idToken)

            return claims
        }
        catch (Exception e) {
            log.warn("Error validating token", e)
            throw new AuthException("Unable to issue token, unable to authenticate with oauth2 provider")
        }
    }

    private PublicKey getPublicKeyFromJwks(String jwks, String kid) {
        def json = objectMapper.readValue(jwks, Map)
        def key = json.keys.find { it.kid == kid }
        if (!key) throw new IllegalArgumentException("Key with kid $kid not found")

        def nBytes = decoder.decode(key.n)
        def eBytes = decoder.decode(key.e)
        def spec = new RSAPublicKeySpec(new BigInteger(1, nBytes), new BigInteger(1, eBytes))
        return KeyFactory.getInstance("RSA").generatePublic(spec)
    }

    private String getKid(String idToken) {
        def header = idToken.split("\\.")[0]
        def decoded = new String(decoder.decode(header), "UTF-8")
        def json = objectMapper.readValue(decoded, Map)
        return json.kid
    }
}
