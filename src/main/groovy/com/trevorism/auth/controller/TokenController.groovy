package com.trevorism.auth.controller

import com.trevorism.auth.errors.AuthException
import com.trevorism.auth.model.AllowedRedirectResponse
import com.trevorism.auth.model.HandoffRedeemRequest
import com.trevorism.auth.model.HandoffRequest
import com.trevorism.auth.model.HandoffResponse
import com.trevorism.auth.model.HandoffTokens
import com.trevorism.auth.model.Identity
import com.trevorism.auth.model.InternalTokenRequest
import com.trevorism.auth.model.RedeemRequest
import com.trevorism.auth.model.TokenRequest
import com.trevorism.auth.service.HandoffService
import com.trevorism.auth.service.RedirectUriPolicy
import com.trevorism.auth.service.TokenService
import com.trevorism.micronaut.SecurityConstants
import com.trevorism.secure.Roles
import com.trevorism.secure.Secure
import io.micronaut.http.HttpRequest
import io.micronaut.http.MediaType
import io.micronaut.http.annotation.Body
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.micronaut.http.annotation.Post
import io.micronaut.http.annotation.QueryValue
import io.micronaut.security.authentication.Authentication
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.tags.Tag
import jakarta.inject.Inject
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.time.Instant
import java.time.temporal.ChronoUnit

@Controller("/token")
class TokenController {

    private static final Logger log = LoggerFactory.getLogger(TokenController)

    @Inject
    private TokenService tokenService
    @Inject
    private HandoffService handoffService
    @Inject
    private RedirectUriPolicy redirectUriPolicy

    @Tag(name = "Token Operations")
    @Operation(summary = "Create a bearer token from valid credentials")
    @Post(value = "/", produces = MediaType.TEXT_PLAIN, consumes = MediaType.APPLICATION_JSON)
    String createToken(@Body TokenRequest tokenRequest) {
        Identity identity = tokenService.getValidatedIdentity(tokenRequest)

        if (identity) {
            log.info("Issuing token for ${identity.id}")
            return tokenService.issueToken(identity, tokenRequest.getAudience())
        }

        throw new AuthException("Unable to issue token, unable to authenticate ${tokenRequest.id}")
    }

    @Tag(name = "Token Operations")
    @Operation(summary = "Create an internal token. **Secure")
    @Post(value = "/internal", produces = MediaType.TEXT_PLAIN, consumes = MediaType.APPLICATION_JSON)
    @Secure(Roles.SYSTEM)
    String createInternalToken(@Body InternalTokenRequest internalTokenRequest, Authentication authentication) {
        if (!internalTokenRequest.subject) {
            throw new AuthException("Unable to issue token, missing subject")
        }
        Identity identity = createIdentityFromInternalTokenRequest(authentication, internalTokenRequest)
        tokenService.issueInternalToken(identity, internalTokenRequest.getAudience(), internalTokenRequest.tenantId)
    }

    @Tag(name = "Token Operations")
    @Operation(summary = "Create a refresh token from valid credentials")
    @Post(value = "/refresh", produces = MediaType.TEXT_PLAIN, consumes = MediaType.APPLICATION_JSON)
    String createRefreshToken(@Body TokenRequest tokenRequest) {
        Identity identity = tokenService.getValidatedIdentity(tokenRequest)

        if (identity) {
            log.info("Issuing token for ${identity.id}")
            return tokenService.issueRefreshToken(identity, tokenRequest.audience)
        }

        throw new AuthException("Unable to issue token, unable to authenticate ${tokenRequest.id}")
    }

    @Tag(name = "Token Operations")
    @Operation(summary = "Redeem a refresh token for a new access token")
    @Post(value = "/refresh/redeem", produces = MediaType.TEXT_PLAIN, consumes = MediaType.APPLICATION_JSON)
    String redeemRefreshToken(@Body RedeemRequest redeemRequest) {
        if (!redeemRequest?.refreshToken) {
            throw new AuthException("Unable to redeem token, missing refresh token")
        }
        return tokenService.redeemRefreshToken(redeemRequest.refreshToken)
    }

    @Tag(name = "Token Operations")
    @Operation(summary = "Exchange the caller's session for a one-time handoff code bound to a redirect URI **Secure")
    @Post(value = "/handoff", produces = MediaType.APPLICATION_JSON, consumes = MediaType.APPLICATION_JSON)
    @Secure(Roles.USER)
    HandoffResponse createHandoffCode(@Body HandoffRequest handoffRequest, Authentication authentication, HttpRequest<?> request) {
        String accessToken = extractCallerToken(request)
        return handoffService.createCode(authentication, accessToken, handoffRequest?.refreshToken, handoffRequest?.redirectUri)
    }

    @Tag(name = "Token Operations")
    @Operation(summary = "Redeem a one-time handoff code for the tokens it carries")
    @Post(value = "/handoff/redeem", produces = MediaType.APPLICATION_JSON, consumes = MediaType.APPLICATION_JSON)
    HandoffTokens redeemHandoffCode(@Body HandoffRedeemRequest redeemRequest) {
        if (!redeemRequest?.code) {
            throw new AuthException("Unable to redeem handoff code, missing code")
        }
        return handoffService.redeemCode(redeemRequest.code, redeemRequest.redirectUri)
    }

    @Tag(name = "Token Operations")
    @Operation(summary = "Reports whether a redirect URI is allowed to receive handoff codes")
    @Get(value = "/handoff/allowed", produces = MediaType.APPLICATION_JSON)
    AllowedRedirectResponse isRedirectAllowed(@QueryValue String uri) {
        return new AllowedRedirectResponse(allowed: redirectUriPolicy.isAllowed(uri))
    }

    static String extractCallerToken(HttpRequest<?> request) {
        String authorization = request.headers.get(SecurityConstants.Http.AUTHORIZATION_HEADER)
        if (authorization && authorization.toLowerCase().startsWith(SecurityConstants.Http.BEARER_PREFIX)) {
            return authorization.substring(SecurityConstants.Http.BEARER_PREFIX.length())
        }
        return request.cookies.get(SecurityConstants.Http.SESSION_COOKIE)?.value
    }

    private static Identity createIdentityFromInternalTokenRequest(authentication, internalTokenRequest) {
        Identity identity = new Identity() {
            @Override
            String getId() {
                authentication.getAttributes().get("id")
            }

            @Override
            String getIdentifer() {
                return internalTokenRequest.subject
            }

            @Override
            boolean isActive() {
                return true
            }

            @Override
            String getTenantGuid() {
                return authentication.getAttributes().get("tenant")
            }

            @Override
            String getPermissions() {
                return null
            }

            @Override
            Date getDateCreated() {
                return new Date()
            }

            @Override
            Date getDateExpired() {
                return Date.from(Instant.now().plus(1, ChronoUnit.HOURS))
            }
        }
        return identity
    }

}
