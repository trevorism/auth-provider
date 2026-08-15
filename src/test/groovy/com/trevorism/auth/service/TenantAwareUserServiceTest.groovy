package com.trevorism.auth.service

import com.trevorism.auth.bean.TenantTokenSecureHttpClientProvider
import com.trevorism.auth.errors.AuthException
import com.trevorism.auth.model.ActivationRequest
import com.trevorism.auth.model.PermissionsRequest
import com.trevorism.auth.model.RegistrationRequest
import com.trevorism.auth.model.TokenRequest
import com.trevorism.auth.model.User
import com.trevorism.data.Repository
import com.trevorism.data.model.filtering.SimpleFilter
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

    @Test
    void testUpdatePermissionsNormalizesToCanonicalOrder() {
        User stored = new User(id: "1", username: "alice", permissions: "R")
        def service = buildServiceOver(stored)

        User result = service.updatePermissions(
                new PermissionsRequest(username: "alice", tenantGuid: "t1", permissions: "edcrucr"),
                auth([Roles.TENANT_ADMIN], [tenant: "t1"]))

        assert result.permissions == "CRUDE"
    }

    @Test
    void testUpdatePermissionsDropsUnsupportedCharacters() {
        User stored = new User(id: "1", username: "alice", permissions: "CRUDE")
        def service = buildServiceOver(stored)

        User result = service.updatePermissions(
                new PermissionsRequest(username: "alice", tenantGuid: "t1", permissions: "R;X X'"),
                auth([Roles.TENANT_ADMIN], [tenant: "t1"]))

        assert result.permissions == "R"
    }

    @Test
    void testUpdatePermissionsClearsWhenNoneRequested() {
        User stored = new User(id: "1", username: "alice", permissions: "CRUDE")
        def service = buildServiceOver(stored)

        User result = service.updatePermissions(
                new PermissionsRequest(username: "alice", tenantGuid: "t1", permissions: null),
                auth([Roles.TENANT_ADMIN], [tenant: "t1"]))

        assert result.permissions == ""
    }

    @Test
    void testUpdatePermissionsPreservesThePasswordAndSaltThatArePersisted() {
        User stored = new User(id: "1", username: "alice", permissions: "R", password: "hashed", salt: "s4lt")
        Map persisted = [:]
        def service = buildServiceOver(stored) { User user ->
            persisted = [password: user.password, salt: user.salt, permissions: user.permissions]
        }

        service.updatePermissions(
                new PermissionsRequest(username: "alice", tenantGuid: "t1", permissions: "CR"),
                auth([Roles.TENANT_ADMIN], [tenant: "t1"]))

        assert persisted.password == "hashed"
        assert persisted.salt == "s4lt"
        assert persisted.permissions == "CR"
    }

    @Test
    void testUpdatePermissionsReturnsACleanedUser() {
        User stored = new User(id: "1", username: "alice", password: "hashed", salt: "s4lt")
        def service = buildServiceOver(stored)

        User result = service.updatePermissions(
                new PermissionsRequest(username: "alice", tenantGuid: "t1", permissions: "R"),
                auth([Roles.TENANT_ADMIN], [tenant: "t1"]))

        assert !result.password
        assert !result.salt
    }

    @Test
    void testUpdatePermissionsTenantAdminCannotCrossTenant() {
        def service = buildServiceOver(new User(id: "1", username: "alice"))
        def request = new PermissionsRequest(username: "alice", tenantGuid: "tenantB", permissions: "R")

        assertThrows(AuthException) {
            service.updatePermissions(request, auth([Roles.TENANT_ADMIN], [tenant: "tenantA"]))
        }
    }

    @Test
    void testUpdatePermissionsGlobalAdminMayTargetAnyTenant() {
        User stored = new User(id: "1", username: "alice", permissions: "R")
        def service = buildServiceOver(stored)

        User result = service.updatePermissions(
                new PermissionsRequest(username: "alice", tenantGuid: "anyTenant", permissions: "CR"),
                auth([Roles.ADMIN], [:]))

        assert result.permissions == "CR"
    }

    @Test
    void testUpdatePermissionsRequiresAUsername() {
        def service = buildServiceOver(new User(id: "1", username: "alice"))

        assertThrows(AuthException) {
            service.updatePermissions(new PermissionsRequest(tenantGuid: "t1", permissions: "R"),
                    auth([Roles.ADMIN], [:]))
        }
    }

    @Test
    void testUpdatePermissionsThrowsWhenTheUserIsMissing() {
        def service = buildServiceOver(null)

        assertThrows(AuthException) {
            service.updatePermissions(new PermissionsRequest(username: "ghost", tenantGuid: "t1", permissions: "R"),
                    auth([Roles.ADMIN], [:]))
        }
    }

    private static TenantAwareUserService buildService() {
        TenantAwareUserService service = new TenantAwareUserService()
        service.generateTokenSecureHttpClientProvider =
                { String tenantId, String audience -> {} as SecureHttpClient } as TenantTokenSecureHttpClientProvider
        return service
    }

    private static TenantAwareUserService buildServiceOver(User stored, Closure onUpdate = null) {
        Repository<User> repository = [
                filter: { SimpleFilter f -> stored ? [stored] : [] },
                update: { String id, User user ->
                    onUpdate?.call(user)
                    return user
                }
        ] as Repository

        TenantAwareUserService service = new TenantAwareUserService() {
            @Override
            protected Repository<User> createUserRepository(String tenantGuid) {
                return repository
            }
        }
        service.generateTokenSecureHttpClientProvider =
                { String tenantId, String audience -> {} as SecureHttpClient } as TenantTokenSecureHttpClientProvider
        return service
    }

    private static Authentication auth(List<String> roles, Map<String, Object> attributes) {
        [getRoles: { roles }, getAttributes: { attributes }] as Authentication
    }
}
