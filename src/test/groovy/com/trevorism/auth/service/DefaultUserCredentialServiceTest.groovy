package com.trevorism.auth.service

import com.trevorism.auth.model.*
import com.trevorism.data.Repository
import com.trevorism.data.model.filtering.ComplexFilter
import com.trevorism.data.model.paging.PageRequest
import com.trevorism.data.model.sorting.ComplexSort
import com.trevorism.https.SecureHttpClient
import com.trevorism.secure.Roles
import io.micronaut.security.authentication.Authentication
import org.junit.jupiter.api.Test

import java.time.Instant

class DefaultUserCredentialServiceTest {

    @Test
    void testGetUser() {
        UserCredentialService service = new DefaultUserCredentialService({} as SecureHttpClient)
        service.repository = new TestUserRepository()
        assert service.getUser("5154038974775296")
        assert !service.getUser("6")
    }

    @Test
    void testDeleteUser() {
        UserCredentialService service = new DefaultUserCredentialService({} as SecureHttpClient)
        service.repository = new TestUserRepository()
        assert service.deleteUser("5154038974775296")
        assert !service.deleteUser("6")
    }

    @Test
    void testListUsers() {
        UserCredentialService service = new DefaultUserCredentialService({} as SecureHttpClient)
        service.repository = new TestUserRepository()
        assert service.listUsers()
    }

    //@Test
    void testRegisterUser() {
        UserCredentialService service = new DefaultUserCredentialService({} as SecureHttpClient)
        service.repository = new TestUserRepository()
        service.emailer = [sendRegistrationEmail: { a, b, c -> }] as Emailer
        assert service.registerUser(new RegistrationRequest(username: "testUsername", email: "testy@trevorism.com", password: "testPass"))
    }

    //@Test
    void testValidateCredentials() {
        UserCredentialService service = new DefaultUserCredentialService({} as SecureHttpClient)
        service.repository = new TestUserRepository()
        assert service.validateCredentials(new TokenRequest(id: "test", password: "testPassword"))
    }

    @Test
    void testValidateCredentials_InvalidPassword() {
        UserCredentialService service = new DefaultUserCredentialService({} as SecureHttpClient)
        service.repository = new TestUserRepository()
        assert !service.validateCredentials(new TokenRequest(id: "test", password: "failPass"))
    }

    @Test
    void testValidateCredentials_MissingValues() {
        UserCredentialService service = new DefaultUserCredentialService({} as SecureHttpClient)
        service.repository = new TestUserRepository()
        assert !service.validateCredentials(new TokenRequest())
    }

    @Test
    void testGetIdentity() {
        UserCredentialService service = new DefaultUserCredentialService({} as SecureHttpClient)
        service.repository = new TestUserRepository()
        assert service.getIdentity("test")
        assert !service.getIdentity("notThere")
    }

    @Test
    void testValidateRegistration() {
        UserCredentialService service = new DefaultUserCredentialService({} as SecureHttpClient)
        service.repository = new TestUserRepository()
        assert service.validateRegistration(new RegistrationRequest(username: "test123", password: "testPassword", email: "testx@trevorism.com"))
    }

    //@Test
    void testChangePassword() {
        UserCredentialService service = new DefaultUserCredentialService({} as SecureHttpClient)
        service.repository = new TestUserRepository()
        assert !service.changePassword(
                new ChangePasswordRequest(username: "test", currentPassword: "b4831cd6bd41ff8", desiredPassword: "b4831cd6bd41ff9"))
    }

    //@Test
    void testForgotPassword() {
        UserCredentialService service = new DefaultUserCredentialService({} as SecureHttpClient)
        service.repository = new TestUserRepository()
        service.emailer = [sendForgotPasswordEmail: { a, b -> }] as Emailer
        service.forgotPassword(new ForgotPasswordRequest(username: "test"))
    }

    //@Test
    void testActivateUser() {
        UserCredentialService service = new DefaultUserCredentialService({} as SecureHttpClient)
        service.repository = new TestUserRepository()
        service.emailer = [sendActivationEmail: { a -> }] as Emailer
        assert service.activateUser(new ActivationRequest(username: "test"), [getRoles: { ->
            [Roles.ADMIN] }, getAttributes                                            : { -> [:] }] as Authentication)
    }

    @Test
    void testDeactivateUser() {
        UserCredentialService service = new DefaultUserCredentialService({} as SecureHttpClient)
        service.repository = new TestUserRepository()
        assert service.deactivateUser(new User(username: "test"))
    }

    @Test
    void testInvalidUserRegistration_missingEmail() {
        UserCredentialService service = new DefaultUserCredentialService({} as SecureHttpClient)
        service.repository = new TestUserRepository()
        assert !service.validateRegistration(new RegistrationRequest(username: "test", password: "test"))
    }

    @Test
    void testValidateRegistration_passwordTooShort() {
        UserCredentialService service = new DefaultUserCredentialService({} as SecureHttpClient)
        service.repository = new TestUserRepository()
        assert !service.validateRegistration(new RegistrationRequest(username: "test123", password: "test", email: "test@trevorism.com"))
    }

    @Test
    void testValidateRegistration_missingUsername() {
        UserCredentialService service = new DefaultUserCredentialService({} as SecureHttpClient)
        service.repository = new TestUserRepository()
        assert !service.validateRegistration(new RegistrationRequest(password: "testPassword", email: "test@trevorism.com"))
    }

    @Test
    void testValidateRegistration_duplicateUsername() {
        UserCredentialService service = new DefaultUserCredentialService({} as SecureHttpClient)
        service.repository = new TestUserRepository()
        assert !service.validateRegistration(new RegistrationRequest(username: "test", password: "testPassword", email: "test@trevorism.com"))
    }

    class TestUserRepository implements Repository<User> {

        @Override
        List<User> all() {
            list()
        }

        @Override
        List<User> list() {
            [new User(username: "test", salt: "5CeJI8KtC6TyTEsHAQCj4g==", email: "test@trevorism.com",
                    password: "tqrJyIlVuOhW79QFzBPgZcOjbR18osSOSUh9pYyzEl+6NqBnqwU8Mal70kKP4TH+qgcwedC9xNkb0gO8HjIYQA==",
                    dateExpired: Date.from(Instant.now().plusSeconds(100)),
                    active: true
            )]
        }

        @Override
        User get(String s) {
            if (s == "5154038974775296")
                return new User()
            return null
        }

        @Override
        User create(User user) {
            return user
        }

        @Override
        User update(String s, User user) {
            return user
        }

        @Override
        User delete(String s) {
            if (s == "5154038974775296")
                return new User()
            return null
        }

        @Override
        void ping() {

        }

        @Override
        List<User> filter(ComplexFilter complexFilter) {
            if (complexFilter?.simpleFilters?.get(0).value == "test")
                return list()
            return []
        }

        @Override
        List<User> page(PageRequest pageRequest) {
            return list()
        }

        @Override
        List<User> sort(ComplexSort complexSort) {
            return list()
        }
    }
}
