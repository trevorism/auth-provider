package com.trevorism.auth.service

import com.trevorism.auth.bean.TenantTokenSecureHttpClientProvider
import com.trevorism.auth.errors.AuthException
import com.trevorism.auth.model.HandoffCode
import com.trevorism.auth.model.HandoffResponse
import com.trevorism.auth.model.HandoffTokens
import com.trevorism.data.Repository
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jwts
import io.micronaut.security.authentication.Authentication
import org.junit.jupiter.api.Test

import static org.junit.jupiter.api.Assertions.assertThrows

class DefaultHandoffServiceTest {

    private static final String REDIRECT_URI = "https://certs.project.trevorism.com/api/auth/callback"

    private Map<String, HandoffCode> store = [:]
    private long nextId = 1000

    private DefaultHandoffService createService(boolean allowed = true) {
        DefaultHandoffService service = new DefaultHandoffService([getSecureHttpClient: { t, a -> null }] as TenantTokenSecureHttpClientProvider)
        service.configuration = new HandoffConfiguration(codeLifetimeSeconds: 60)
        service.redirectUriPolicy = [isAllowed: { String uri -> allowed }] as RedirectUriPolicy
        service.tokenService = [validateRefreshToken: { String token -> claimsFor(token) }] as TokenService
        service.@repository = [
                create: { HandoffCode code -> code.id = "${nextId++}"; store[code.id] = code; return code },
                get: { String id -> store[id] },
                delete: { String id -> store.remove(id) }
        ] as Repository<HandoffCode>
        return service
    }

    private static Claims claimsFor(String token) {
        if (token == "bad") {
            throw new AuthException("Invalid refresh token")
        }
        String[] parts = token.split(":")
        def builder = Jwts.claims().subject(parts[0])
        if (parts.length > 1) {
            builder.add("tenant", parts[1])
        }
        return builder.build()
    }

    private static Authentication authentication(String name = "tester", String tenant = null) {
        Map attributes = tenant ? [tenant: tenant] : [:]
        return [getName: { -> name }, getAttributes: { -> attributes }, getRoles: { -> ["user"] }] as Authentication
    }

    @Test
    void testRoundTrip() {
        DefaultHandoffService service = createService()
        HandoffResponse response = service.createCode(authentication(), "access.jwt", "tester", REDIRECT_URI)

        assert response.code.matches(/\d+\.[A-Za-z0-9_-]{43}/)
        assert response.expiresInSeconds == 60
        HandoffCode stored = store.values().first()
        assert stored.secretHash != response.code.split(/\./)[1]
        assert stored.subject == "tester"

        HandoffTokens tokens = service.redeemCode(response.code, REDIRECT_URI)
        assert tokens.accessToken == "access.jwt"
        assert tokens.refreshToken == "tester"
    }

    @Test
    void testCodeIsSingleUse() {
        DefaultHandoffService service = createService()
        HandoffResponse response = service.createCode(authentication(), "access.jwt", null, REDIRECT_URI)
        service.redeemCode(response.code, REDIRECT_URI)
        assertThrows(AuthException, () -> service.redeemCode(response.code, REDIRECT_URI))
    }

    @Test
    void testRedeemRequiresMatchingRedirectUri() {
        DefaultHandoffService service = createService()
        HandoffResponse response = service.createCode(authentication(), "access.jwt", null, REDIRECT_URI)
        assertThrows(AuthException, () -> service.redeemCode(response.code, "https://evil.example.org/api/auth/callback"))
        assert store.isEmpty()
    }

    @Test
    void testRedeemRejectsTamperedSecret() {
        DefaultHandoffService service = createService()
        HandoffResponse response = service.createCode(authentication(), "access.jwt", null, REDIRECT_URI)
        String lastChar = response.code[-1]
        String tampered = response.code[0..-2] + (lastChar == "A" ? "B" : "A")
        assertThrows(AuthException, () -> service.redeemCode(tampered, REDIRECT_URI))
        assert store.size() == 1
        assert service.redeemCode(response.code, REDIRECT_URI).accessToken == "access.jwt"
    }

    @Test
    void testGuessedIdCannotBurnACode() {
        DefaultHandoffService service = createService()
        HandoffResponse response = service.createCode(authentication(), "access.jwt", null, REDIRECT_URI)
        String id = response.code.split(/\./)[0]

        assertThrows(AuthException, () -> service.redeemCode("${id}.notTheSecret", REDIRECT_URI))
        assert store.size() == 1
        assert service.redeemCode(response.code, REDIRECT_URI).accessToken == "access.jwt"
        assert store.isEmpty()
    }

    @Test
    void testRedeemRejectsExpiredCode() {
        DefaultHandoffService service = createService()
        HandoffResponse response = service.createCode(authentication(), "access.jwt", null, REDIRECT_URI)
        store.values().first().dateExpired = new Date(System.currentTimeMillis() - 1000)
        assertThrows(AuthException, () -> service.redeemCode(response.code, REDIRECT_URI))
    }

    @Test
    void testRedeemRejectsMalformedCodes() {
        DefaultHandoffService service = createService()
        assertThrows(AuthException, () -> service.redeemCode(null, REDIRECT_URI))
        assertThrows(AuthException, () -> service.redeemCode("", REDIRECT_URI))
        assertThrows(AuthException, () -> service.redeemCode("nodot", REDIRECT_URI))
        assertThrows(AuthException, () -> service.redeemCode("abc.secret", REDIRECT_URI))
        assertThrows(AuthException, () -> service.redeemCode("123.", REDIRECT_URI))
        assertThrows(AuthException, () -> service.redeemCode("999999.secret", REDIRECT_URI))
    }

    @Test
    void testRedeemTreatsDatastoreFailureAsInvalid() {
        DefaultHandoffService service = createService()
        service.@repository = [get: { String id -> throw new RuntimeException("down") }] as Repository<HandoffCode>
        assertThrows(AuthException, () -> service.redeemCode("123.secret", REDIRECT_URI))
    }

    @Test
    void testRedeemFailsWhenCodeCannotBeConsumed() {
        DefaultHandoffService service = createService()
        HandoffResponse response = service.createCode(authentication(), "access.jwt", null, REDIRECT_URI)
        service.@repository = [
                get: { String id -> store[id] },
                delete: { String id -> throw new RuntimeException("down") }
        ] as Repository<HandoffCode>
        assertThrows(AuthException, () -> service.redeemCode(response.code, REDIRECT_URI))
    }

    @Test
    void testCreateRejectsDisallowedRedirectUri() {
        DefaultHandoffService service = createService(false)
        assertThrows(AuthException, () -> service.createCode(authentication(), "access.jwt", null, "https://evil.example.org/api/auth/callback"))
        assert store.isEmpty()
    }

    @Test
    void testCreateRequiresAccessTokenAndRedirectUri() {
        DefaultHandoffService service = createService()
        assertThrows(AuthException, () -> service.createCode(authentication(), null, null, REDIRECT_URI))
        assertThrows(AuthException, () -> service.createCode(authentication(), "access.jwt", null, null))
    }

    @Test
    void testCreateRejectsRefreshTokenForAnotherSubject() {
        DefaultHandoffService service = createService()
        assertThrows(AuthException, () -> service.createCode(authentication("tester"), "access.jwt", "someoneElse", REDIRECT_URI))
        assertThrows(AuthException, () -> service.createCode(authentication("tester"), "access.jwt", "bad", REDIRECT_URI))
        assert store.isEmpty()
    }

    @Test
    void testCreateRejectsRefreshTokenForAnotherTenant() {
        DefaultHandoffService service = createService()
        assertThrows(AuthException, () -> service.createCode(authentication("tester", "tenant-a"), "access.jwt", "tester:tenant-b", REDIRECT_URI))
        assert service.createCode(authentication("tester", "tenant-a"), "access.jwt", "tester:tenant-a", REDIRECT_URI).code
    }

    @Test
    void testHashIsDeterministicAndOneWay() {
        assert DefaultHandoffService.hash("secret") == DefaultHandoffService.hash("secret")
        assert DefaultHandoffService.hash("secret") != DefaultHandoffService.hash("secret2")
        assert !DefaultHandoffService.hash("secret").contains("secret")
    }
}
