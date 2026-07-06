package com.trevorism.auth.service

import com.trevorism.auth.bean.TenantTokenSecureHttpClientProvider
import com.trevorism.auth.errors.AuthException
import com.trevorism.auth.model.ActivationRequest
import com.trevorism.auth.model.RegistrationRequest
import com.trevorism.auth.model.TokenRequest
import com.trevorism.https.SecureHttpClient
import com.trevorism.secure.Roles
import io.micronaut.security.authentication.Authentication
import org.junit.jupiter.api.Test

import static org.junit.jupiter.api.Assertions.assertThrows

class TenantAwareUserServiceTest {

    @Test
    void testValidateCredentialsNullRequest() {
        assert !buildService().validateCredentials(null)
    }

    @Test
    void testValidateCredentialsMissingUsername() {
        assert !buildService().validateCredentials(new TokenRequest(id: null, password: "secret"))
    }

    @Test
    void testValidateCredentialsMissingPassword() {
        assert !buildService().validateCredentials(new TokenRequest(id: "user", password: ""))
    }

    @Test
    void testRegisterUserMissingUsername() {
        def request = new RegistrationRequest(username: null, password: "secret1", email: "a@trevorism.com")
        assertThrows(AuthException) { buildService().registerUser(request) }
    }

    @Test
    void testRegisterUserShortUsername() {
        def request = new RegistrationRequest(username: "ab", password: "secret1", email: "a@trevorism.com")
        assertThrows(AuthException) { buildService().registerUser(request) }
    }

    @Test
    void testRegisterUserShortPassword() {
        def request = new RegistrationRequest(username: "alice", password: "short", email: "a@trevorism.com")
        assertThrows(AuthException) { buildService().registerUser(request) }
    }

    @Test
    void testRegisterUserInvalidEmail() {
        def request = new RegistrationRequest(username: "alice", password: "secret1", email: "not-an-email")
        assertThrows(AuthException) { buildService().registerUser(request) }
    }

    @Test
    void testActivateUserNonAdminCannotActivateAdmin() {
        def request = new ActivationRequest(username: "alice", tenantGuid: "t1", isAdmin: true)
        assertThrows(AuthException) {
            buildService().activateUser(request, auth([Roles.USER], [:]))
        }
    }

    @Test
    void testActivateUserTenantAdminCannotCrossTenant() {
        def request = new ActivationRequest(username: "alice", tenantGuid: "tenantB", isAdmin: false)
        assertThrows(AuthException) {
            buildService().activateUser(request, auth([Roles.ADMIN], [tenant: "tenantA"]))
        }
    }

    @Test
    void testDeactivateUserNonAdminCannotTargetAdmin() {
        def request = new ActivationRequest(username: "alice", tenantGuid: "t1", isAdmin: true)
        assertThrows(AuthException) {
            buildService().deactivateUser(request, auth([Roles.USER], [:]))
        }
    }

    private static TenantAwareUserService buildService() {
        TenantAwareUserService service = new TenantAwareUserService()
        service.generateTokenSecureHttpClientProvider =
                { String tenantId, String audience -> {} as SecureHttpClient } as TenantTokenSecureHttpClientProvider
        return service
    }

    private static Authentication auth(List<String> roles, Map<String, Object> attributes) {
        [getRoles: { roles }, getAttributes: { attributes }] as Authentication
    }
}
