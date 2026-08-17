package com.trevorism.auth.service

import com.trevorism.auth.bean.TenantTokenSecureHttpClientProvider
import com.trevorism.auth.errors.AuthException
import com.trevorism.auth.model.ActivationRequest
import com.trevorism.auth.model.ChangePasswordRequest
import com.trevorism.auth.model.ForgotPasswordRequest
import com.trevorism.auth.model.PermissionsRequest
import com.trevorism.auth.model.RegistrationRequest
import com.trevorism.auth.model.SaltedPassword
import com.trevorism.auth.model.TokenRequest
import com.trevorism.auth.model.User
import com.trevorism.data.Repository
import com.trevorism.data.model.filtering.SimpleFilter
import com.trevorism.https.SecureHttpClient
import com.trevorism.secure.Permissions
import com.trevorism.secure.Roles
import io.micronaut.security.authentication.Authentication
import org.junit.jupiter.api.Test

import java.lang.reflect.Field
import java.time.Instant
import java.time.temporal.ChronoUnit

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
    void testActivateUserTenantAdminCannotGrantAdmin() {
        def request = new ActivationRequest(username: "alice", tenantGuid: "t1", isAdmin: true)
        assertThrows(AuthException) {
            buildService().activateUser(request, auth([Roles.TENANT_ADMIN], [tenant: "t1"]))
        }
    }

    @Test
    void testActivateUserSystemCanGrantTenantAdmin() {
        Map persisted = [:]
        def service = buildServiceWith(repositoryOf([userWithPassword("alice", "secret1", [active: false])], persisted))

        assert service.activateUser(new ActivationRequest(username: "alice", tenantGuid: "t1", isAdmin: true),
                auth([Roles.SYSTEM], [:]))

        assert persisted.updated.active
        assert persisted.updated.admin
    }

    @Test
    void testActivateUserSystemCannotGrantGlobalAdmin() {
        def request = new ActivationRequest(username: "alice", isAdmin: true)
        assertThrows(AuthException) {
            buildService().activateUser(request, auth([Roles.SYSTEM], [:]))
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

    @Test
    void testRegisterUserHashesThePasswordAndLowercasesIdentifiers() {
        Map persisted = [:]
        def service = buildServiceWith(repositoryOf([], persisted))

        User result = service.registerUser(new RegistrationRequest(username: "Alice", password: "secret1",
                email: "Alice@Trevorism.com", tenantGuid: "t1"))

        assert persisted.created.username == "alice"
        assert persisted.created.email == "alice@trevorism.com"
        assert persisted.created.password != "secret1"
        assert HashUtils.validatePasswordsMatch(
                new SaltedPassword(persisted.created.salt, persisted.created.password), "secret1")
        assert persisted.created.dateCreated
        assert !result.password
        assert !result.salt
    }

    @Test
    void testRegisterUserOnTheDefaultTenantIsInactiveWithBaselinePermissions() {
        Map persisted = [:]
        def service = buildServiceWith(repositoryOf([], persisted))

        service.registerUser(new RegistrationRequest(username: "alice", password: "secret1",
                email: "alice@trevorism.com", autoRegister: true))

        assert !persisted.created.active
        assert persisted.created.permissions == "${Permissions.CREATE}${Permissions.READ}${Permissions.EXECUTE}"
        assert !persisted.created.dateExpired
    }

    @Test
    void testRegisterUserOnATenantHonorsAutoRegisterAndSetsExpiry() {
        Map persisted = [:]
        def service = buildServiceWith(repositoryOf([], persisted))

        service.registerUser(new RegistrationRequest(username: "alice", password: "secret1",
                email: "alice@trevorism.com", tenantGuid: "t1", autoRegister: true, permissions: "R"))

        assert persisted.created.active
        assert persisted.created.permissions == "R"
        assert persisted.created.dateExpired.after(new Date())
    }

    @Test
    void testRegisterUserRejectsADuplicateUsernameRegardlessOfCase() {
        def service = buildServiceWith(repositoryOf([new User(username: "alice", email: "alice@trevorism.com")]))
        def request = new RegistrationRequest(username: "ALICE", password: "secret1", email: "other@trevorism.com")

        assertThrows(AuthException) { service.registerUser(request) }
    }

    @Test
    void testRegisterUserRejectsADuplicateEmail() {
        def service = buildServiceWith(repositoryOf([new User(username: "alice", email: "alice@trevorism.com")]))
        def request = new RegistrationRequest(username: "bob", password: "secret1", email: "Alice@trevorism.com")

        assertThrows(AuthException) { service.registerUser(request) }
    }

    @Test
    void testRegisterUserNotifiesTheSiteAdminUnlessSuppressed() {
        def emailer = new RecordingEmailer()
        def service = buildServiceWith(repositoryOf([]), emailer)

        service.registerUser(new RegistrationRequest(username: "alice", password: "secret1",
                email: "alice@trevorism.com", tenantGuid: "t1"))

        assert emailer.sent.size() == 1
        assert emailer.sent[0].type == "registration"
        assert emailer.sent[0].username == "alice"
        assert emailer.sent[0].tenantGuid == "t1"

        service.registerUser(new RegistrationRequest(username: "bob", password: "secret1",
                email: "bob@trevorism.com", tenantGuid: "t1", doNotNotifySiteAdminOfRegistration: true))

        assert emailer.sent.size() == 1
    }

    @Test
    void testForgotPasswordThrowsWhenTheUserIsMissing() {
        def service = buildServiceWith(repositoryOf([]))

        assertThrows(AuthException) {
            service.forgotPassword(new ForgotPasswordRequest(username: "ghost", tenantGuid: "t1"))
        }
    }

    @Test
    void testForgotPasswordEmailsAPasswordThatMatchesWhatIsPersisted() {
        Map persisted = [:]
        def emailer = new RecordingEmailer()
        def service = buildServiceWith(repositoryOf([userWithPassword("alice", "secret1")], persisted), emailer)

        User result = service.forgotPassword(new ForgotPasswordRequest(username: "alice", tenantGuid: "t1"))

        assert emailer.sent[0].type == "forgotPassword"
        assert emailer.sent[0].audience == "trevorism.com"
        assert HashUtils.validatePasswordsMatch(
                new SaltedPassword(persisted.updated.salt, persisted.updated.password), emailer.sent[0].password)
        assert !result.password
        assert !result.salt
    }

    @Test
    void testForgotPasswordExpiresTheTemporaryPasswordInADay() {
        Map persisted = [:]
        def service = buildServiceWith(repositoryOf([userWithPassword("alice", "secret1")], persisted))

        service.forgotPassword(new ForgotPasswordRequest(username: "alice", tenantGuid: "t1"))

        Date expiry = persisted.updated.dateExpired
        assert expiry.after(new Date())
        assert expiry.before(Date.from(Instant.now().plus(2, ChronoUnit.DAYS)))
    }

    @Test
    void testActivateUserActivatesGrantsAdminAndSetsExpiry() {
        Map persisted = [:]
        def service = buildServiceWith(repositoryOf([userWithPassword("alice", "secret1", [active: false])], persisted))

        assert service.activateUser(new ActivationRequest(username: "alice", tenantGuid: "t1", isAdmin: true),
                auth([Roles.ADMIN], [:]))

        assert persisted.updated.active
        assert persisted.updated.admin
        assert persisted.updated.dateExpired.after(new Date())
    }

    @Test
    void testActivateUserReturnsFalseWhenThePersistFails() {
        def repository = repositoryOf([userWithPassword("alice", "secret1")], [:]) { null }
        def service = buildServiceWith(repository)

        assert !service.activateUser(new ActivationRequest(username: "alice", tenantGuid: "t1"), auth([Roles.ADMIN], [:]))
    }

    @Test
    void testActivateUserSendsTheWelcomeEmailOnlyWhenRequested() {
        def emailer = new RecordingEmailer()
        def service = buildServiceWith(repositoryOf([userWithPassword("alice", "secret1")]), emailer)

        service.activateUser(new ActivationRequest(username: "alice", tenantGuid: "t1"), auth([Roles.ADMIN], [:]))
        assert emailer.sent.isEmpty()

        service.activateUser(new ActivationRequest(username: "alice", tenantGuid: "t1", doNotSendWelcomeEmail: false),
                auth([Roles.ADMIN], [:]))

        assert emailer.sent[0].type == "activation"
        assert emailer.sent[0].email == "alice@trevorism.com"
        assert emailer.sent[0].tenantGuid == "t1"
    }

    @Test
    void testDeactivateUserClearsTheActiveFlag() {
        Map persisted = [:]
        def service = buildServiceWith(repositoryOf([userWithPassword("alice", "secret1")], persisted))

        assert service.deactivateUser(new ActivationRequest(username: "alice", tenantGuid: "t1"), auth([Roles.ADMIN], [:]))
        assert !persisted.updated.active
    }

    @Test
    void testValidateCredentialsAcceptsTheMatchingPassword() {
        def service = buildServiceWith(repositoryOf([userWithPassword("alice", "secret1")]))

        assert service.validateCredentials(new TokenRequest(id: "alice", password: "secret1", tenantGuid: "t1"))
    }

    @Test
    void testValidateCredentialsRejectsTheWrongPassword() {
        def service = buildServiceWith(repositoryOf([userWithPassword("alice", "secret1")]))

        assert !service.validateCredentials(new TokenRequest(id: "alice", password: "secret2", tenantGuid: "t1"))
    }

    @Test
    void testValidateCredentialsRejectsAnInactiveUser() {
        def service = buildServiceWith(repositoryOf([userWithPassword("alice", "secret1", [active: false])]))

        assert !service.validateCredentials(new TokenRequest(id: "alice", password: "secret1", tenantGuid: "t1"))
    }

    @Test
    void testValidateCredentialsRejectsAnExpiredUser() {
        User expired = userWithPassword("alice", "secret1",
                [dateExpired: Date.from(Instant.now().minus(1, ChronoUnit.DAYS))])
        def service = buildServiceWith(repositoryOf([expired]))

        assert !service.validateCredentials(new TokenRequest(id: "alice", password: "secret1", tenantGuid: "t1"))
    }

    @Test
    void testValidateCredentialsRejectsAnUnknownUser() {
        def service = buildServiceWith(repositoryOf([]))

        assert !service.validateCredentials(new TokenRequest(id: "ghost", password: "secret1", tenantGuid: "t1"))
    }

    @Test
    void testGetCurrentUserReadsTheIdFromTheAuthenticationAndCleansTheResult() {
        def service = buildServiceWith(repositoryOf([userWithPassword("alice", "secret1")]))

        User result = service.getCurrentUser(auth([Roles.USER], [id: "1", tenant: "t1"]))

        assert result.username == "alice"
        assert !result.password
        assert !result.salt
    }

    @Test
    void testChangePasswordRejectsTheWrongCurrentPassword() {
        Map persisted = [:]
        def service = buildServiceWith(repositoryOf([userWithPassword("alice", "secret1")], persisted))

        assert !service.changePassword(new ChangePasswordRequest(username: "alice", currentPassword: "wrong",
                desiredPassword: "secret2", tenantGuid: "t1"))
        assert !persisted.updated
    }

    @Test
    void testChangePasswordStoresTheDesiredPasswordAndExtendsExpiry() {
        Map persisted = [:]
        def service = buildServiceWith(repositoryOf([userWithPassword("alice", "secret1")], persisted))

        assert service.changePassword(new ChangePasswordRequest(username: "alice", currentPassword: "secret1",
                desiredPassword: "secret2", tenantGuid: "t1"))

        assert HashUtils.validatePasswordsMatch(
                new SaltedPassword(persisted.updated.salt, persisted.updated.password), "secret2")
        assert persisted.updated.dateExpired.after(Date.from(Instant.now().plus(300, ChronoUnit.DAYS)))
    }

    @Test
    void testGetIdentityReturnsTheMatchingUser() {
        def service = buildServiceWith(repositoryOf([userWithPassword("alice", "secret1")]))

        assert service.getIdentity(new TokenRequest(id: "alice", tenantGuid: "t1")).identifer == "alice"
    }

    @Test
    void testGetIdentityReturnsNullWhenTheUserIsMissing() {
        def service = buildServiceWith(repositoryOf([]))

        assert !service.getIdentity(new TokenRequest(id: "ghost", tenantGuid: "t1"))
    }

    @Test
    void testRepositoryIsScopedToTheRequestedTenantAndAudience() {
        Map factoryArgs = [:]
        def service = buildServiceWith(repositoryOf([]), new RecordingEmailer(), factoryArgs)

        service.getIdentity(new TokenRequest(id: "alice", tenantGuid: "t9", audience: "example.com"))

        assert factoryArgs.tenantGuid == "t9"
        assert factoryArgs.audience == "example.com"
    }

    @Test
    void testActivationRepositoryIsScopedToTheTenantWithoutAnAudience() {
        Map factoryArgs = [:]
        def service = buildServiceWith(repositoryOf([userWithPassword("alice", "secret1")]),
                new RecordingEmailer(), factoryArgs)

        service.activateUser(new ActivationRequest(username: "alice", tenantGuid: "t9"), auth([Roles.ADMIN], [:]))

        assert factoryArgs.tenantGuid == "t9"
        assert !factoryArgs.audience
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
            protected Repository<User> createUserRepository(String tenantGuid, String audience) {
                return repository
            }
        }
        service.generateTokenSecureHttpClientProvider =
                { String tenantId, String audience -> {} as SecureHttpClient } as TenantTokenSecureHttpClientProvider
        return service
    }

    private static TenantAwareUserService buildServiceWith(Repository<User> repository,
                                                           Emailer emailer = new RecordingEmailer(),
                                                           Map factoryArgs = [:]) {
        TenantAwareUserService service = new TenantAwareUserService() {
            @Override
            protected Repository<User> createUserRepository(String tenantGuid, String audience) {
                factoryArgs.tenantGuid = tenantGuid
                factoryArgs.audience = audience
                return repository
            }
        }
        service.generateTokenSecureHttpClientProvider =
                { String tenantId, String audience -> {} as SecureHttpClient } as TenantTokenSecureHttpClientProvider
        Field field = TenantAwareUserService.getDeclaredField("emailer")
        field.setAccessible(true)
        field.set(service, emailer)
        return service
    }

    private static Repository<User> repositoryOf(List<User> users, Map recorder = [:], Closure onUpdate = null) {
        return [
                list  : { users },
                get   : { String id -> users.find { it.id == id } },
                filter: { SimpleFilter f -> users.findAll { it.username == f.value } },
                create: { User user ->
                    recorder.created = snapshot(user)
                    return user
                },
                update: { String id, User user ->
                    recorder.updated = snapshot(user)
                    return onUpdate ? onUpdate.call(user) : user
                }
        ] as Repository
    }

    private static Map snapshot(User user) {
        return [id: user.id, username: user.username, email: user.email, password: user.password,
                salt: user.salt, permissions: user.permissions, active: user.active, admin: user.admin,
                dateCreated: user.dateCreated, dateExpired: user.dateExpired]
    }

    private static User userWithPassword(String username, String rawPassword, Map overrides = [:]) {
        SaltedPassword saltedPassword = HashUtils.createPasswordAndSalt(rawPassword)
        User user = new User(id: "1", username: username, email: "${username}@trevorism.com",
                password: saltedPassword.password, salt: saltedPassword.salt, active: true,
                dateExpired: Date.from(Instant.now().plus(1, ChronoUnit.DAYS)))
        overrides.each { key, value -> user[key] = value }
        return user
    }

    private static Authentication auth(List<String> roles, Map<String, Object> attributes) {
        [getRoles: { roles }, getAttributes: { attributes }] as Authentication
    }

    private static class RecordingEmailer extends Emailer {

        List<Map> sent = []

        RecordingEmailer() {
            super({ String tenantId, String audience -> {} as SecureHttpClient } as TenantTokenSecureHttpClientProvider)
        }

        @Override
        boolean sendRegistrationEmailToNotifySiteAdmin(String username, String emailAddress, String tenantGuid) {
            sent << [type: "registration", username: username, email: emailAddress, tenantGuid: tenantGuid]
            return true
        }

        @Override
        boolean sendForgotPasswordEmail(String emailAddress, String username, String newPassword, String audience) {
            sent << [type: "forgotPassword", email: emailAddress, username: username,
                     password: newPassword, audience: audience]
            return true
        }

        @Override
        boolean sendActivationEmail(String emailAddress, String tenantGuid) {
            sent << [type: "activation", email: emailAddress, tenantGuid: tenantGuid]
            return true
        }
    }
}
