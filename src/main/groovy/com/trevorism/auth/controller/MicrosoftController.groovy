package com.trevorism.auth.controller

import com.fasterxml.jackson.databind.ObjectMapper
import com.trevorism.auth.errors.AuthException
import com.trevorism.auth.model.Oauth2Tokens
import com.trevorism.auth.model.SupportedOauth2Provider
import com.trevorism.auth.service.TokenService
import com.trevorism.http.HttpClient
import com.trevorism.http.JsonHttpClient
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jws
import io.jsonwebtoken.Jwts
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Body
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Post
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.inject.Inject
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.RSAPublicKeySpec

@Controller("/microsoft")
class MicrosoftController {

    private static final Logger log = LoggerFactory.getLogger(MicrosoftController)

    public static final String tenantId = "d77da90e-329a-41c3-b8b7-f76b8bf71b06"
    public static final String clientId = "c3ede79b-cc30-4f21-818c-45f727113b0e"

    @Inject
    private TokenService tokenService
    private ObjectMapper objectMapper = new ObjectMapper()
    private Base64.Decoder decoder = Base64.getUrlDecoder()

    @Tag(name = "Microsoft Operations")
    @Operation(summary = "Create a token from a validated Microsoft token")
    @Post(value = "/", produces = MediaType.TEXT_PLAIN, consumes = MediaType.APPLICATION_JSON)
    String createToken(@Body Oauth2Tokens tokens) {
        try {
            String url = "https://login.microsoftonline.com/${tenantId}/discovery/v2.0/keys?appid=${clientId}"
            String kid = getKid(tokens.id_token)

            HttpClient httpClient = new JsonHttpClient()
            def jwksResponse = httpClient.get(url)
            PublicKey publicKey = getPublicKeyFromJwks(jwksResponse, kid)

            Jws<Claims> claims = Jwts.parser()
                    .verifyWith(publicKey)
                    .requireIssuer("https://sts.windows.net/${tenantId}/")
                    .requireAudience(clientId)
                    .clockSkewSeconds(10)
                    .build().parseSignedClaims(tokens.id_token)

            return tokenService.issueTokenFromOauthProvider(SupportedOauth2Provider.Microsoft, claims)
        }
        catch (Exception e) {
            log.warn("Error validating Microsoft token", e)
            throw new AuthException("Unable to issue token, unable to authenticate with Microsoft")
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
