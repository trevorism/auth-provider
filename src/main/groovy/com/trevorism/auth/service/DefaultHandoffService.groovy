package com.trevorism.auth.service

import com.trevorism.auth.bean.TenantTokenSecureHttpClientProvider
import com.trevorism.auth.errors.AuthException
import com.trevorism.auth.model.HandoffCode
import com.trevorism.auth.model.HandoffResponse
import com.trevorism.auth.model.HandoffTokens
import com.trevorism.data.FastDatastoreRepository
import com.trevorism.data.Repository
import io.jsonwebtoken.Claims
import io.micronaut.security.authentication.Authentication
import jakarta.inject.Inject
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Instant

@jakarta.inject.Singleton
class DefaultHandoffService implements HandoffService {

    private static final Logger log = LoggerFactory.getLogger(DefaultHandoffService)
    private static final String INVALID_CODE = "Invalid handoff code"
    private static final int SECRET_BYTES = 32

    @Inject
    RedirectUriPolicy redirectUriPolicy
    @Inject
    TokenService tokenService
    @Inject
    HandoffConfiguration configuration

    private final SecureRandom secureRandom = new SecureRandom()
    private Repository<HandoffCode> repository

    DefaultHandoffService(TenantTokenSecureHttpClientProvider tokenSecureHttpClientProvider) {
        repository = new FastDatastoreRepository<>(HandoffCode, tokenSecureHttpClientProvider.getSecureHttpClient(null, null))
    }

    @Override
    HandoffResponse createCode(Authentication authentication, String accessToken, String refreshToken, String redirectUri) {
        if (!accessToken) {
            throw new AuthException("Unable to hand off, missing access token")
        }
        if (!redirectUri) {
            throw new AuthException("Unable to hand off, missing redirectUri")
        }
        if (!redirectUriPolicy.isAllowed(redirectUri)) {
            throw new AuthException("Unable to hand off, redirectUri is not allowed")
        }
        if (refreshToken) {
            validateRefreshTokenBelongsToCaller(authentication, refreshToken)
        }

        String secret = generateSecret()
        Instant now = Instant.now()
        HandoffCode handoffCode = new HandoffCode(
                secretHash: hash(secret),
                redirectUri: redirectUri,
                subject: authentication.name,
                accessToken: accessToken,
                refreshToken: refreshToken,
                dateCreated: Date.from(now),
                dateExpired: Date.from(now.plusSeconds(configuration.codeLifetimeSeconds)))
        HandoffCode created = repository.create(handoffCode)
        log.info("Issued handoff code for ${authentication.name} to ${redirectUri}")
        return new HandoffResponse(code: "${created.id}.${secret}", expiresInSeconds: configuration.codeLifetimeSeconds)
    }

    @Override
    HandoffTokens redeemCode(String code, String redirectUri) {
        HandoffCode stored = consume(code)
        String secret = code.substring(code.indexOf('.') + 1)

        if (!constantTimeEquals(stored.secretHash, hash(secret))) {
            throw new AuthException(INVALID_CODE)
        }
        if (!stored.dateExpired || stored.dateExpired.before(new Date())) {
            throw new AuthException(INVALID_CODE)
        }
        if (!redirectUri || stored.redirectUri != redirectUri) {
            throw new AuthException(INVALID_CODE)
        }
        log.info("Redeemed handoff code for ${stored.subject} at ${redirectUri}")
        return new HandoffTokens(accessToken: stored.accessToken, refreshToken: stored.refreshToken)
    }

    private HandoffCode consume(String code) {
        int separator = code ? code.indexOf('.') : -1
        if (separator <= 0 || separator == code.length() - 1) {
            throw new AuthException(INVALID_CODE)
        }
        String id = code.substring(0, separator)
        if (!id.isLong()) {
            throw new AuthException(INVALID_CODE)
        }
        HandoffCode stored
        try {
            stored = repository.delete(id)
        } catch (Exception e) {
            log.debug("Unable to delete handoff code ${id}: ${e.message}")
            throw new AuthException(INVALID_CODE)
        }
        if (!stored?.secretHash) {
            throw new AuthException(INVALID_CODE)
        }
        return stored
    }

    private void validateRefreshTokenBelongsToCaller(Authentication authentication, String refreshToken) {
        Claims claims = tokenService.validateRefreshToken(refreshToken)
        String callerTenant = authentication.attributes.get("tenant")
        if (claims.subject != authentication.name || claims.get("tenant", String) != callerTenant) {
            throw new AuthException("Unable to hand off, refresh token does not belong to the caller")
        }
    }

    private String generateSecret() {
        byte[] bytes = new byte[SECRET_BYTES]
        secureRandom.nextBytes(bytes)
        return Base64.urlEncoder.withoutPadding().encodeToString(bytes)
    }

    static String hash(String secret) {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(secret.getBytes(StandardCharsets.UTF_8))
        return Base64.urlEncoder.withoutPadding().encodeToString(digest)
    }

    private static boolean constantTimeEquals(String expected, String actual) {
        if (!expected || !actual) {
            return false
        }
        return MessageDigest.isEqual(expected.getBytes(StandardCharsets.UTF_8), actual.getBytes(StandardCharsets.UTF_8))
    }
}
