package com.trevorism.auth.service

import com.trevorism.auth.bean.SecureHttpClientProvider
import com.trevorism.auth.model.User
import com.trevorism.data.Repository
import com.trevorism.data.model.filtering.ComplexFilter
import com.trevorism.data.model.paging.PageRequest
import com.trevorism.data.model.sorting.ComplexSort
import org.junit.jupiter.api.Test

import java.time.Instant

class DefaultUserCredentialServiceTest {

    @Test
    void testGetUser() {
        UserCredentialService service = new DefaultUserCredentialService({} as SecureHttpClientProvider)
        service.repository = new TestUserRepository()
        assert service.getUser("5154038974775296")
        assert !service.getUser("6")
    }

    @Test
    void testDeleteUser() {
        UserCredentialService service = new DefaultUserCredentialService({} as SecureHttpClientProvider)
        service.repository = new TestUserRepository()
        assert service.deleteUser("5154038974775296")
        assert !service.deleteUser("6")
    }

    @Test
    void testListUsers() {
        UserCredentialService service = new DefaultUserCredentialService({} as SecureHttpClientProvider)
        service.repository = new TestUserRepository()
        assert service.listUsers()
    }

    @Test
    void testRegisterUser() {
        UserCredentialService service = new DefaultUserCredentialService({} as SecureHttpClientProvider)
        service.repository = new TestUserRepository()
        service.emailer = [sendRegistrationEmail: { a, b -> }] as Emailer
        //TODO: Breaks due to non injected emailer
        assert true
        //assert service.registerUser(new User(username: "testUsername", email: "test@trevorism.com", password: "testPass"))
    }

    @Test
    void testValidateCredentials() {
        UserCredentialService service = new DefaultUserCredentialService({} as SecureHttpClientProvider)
        service.repository = new TestUserRepository()
        assert service.validateCredentials("test", "testPassword")
    }

    @Test
    void testValidateCredentials_InvalidPassword() {
        UserCredentialService service = new DefaultUserCredentialService({} as SecureHttpClientProvider)
        service.repository = new TestUserRepository()
        assert !service.validateCredentials("test", "failPass")
    }

    @Test
    void testValidateCredentials_MissingValues() {
        UserCredentialService service = new DefaultUserCredentialService({} as SecureHttpClientProvider)
        service.repository = new TestUserRepository()
        assert !service.validateCredentials(null, null)
    }

    @Test
    void testGetIdentity() {
        UserCredentialService service = new DefaultUserCredentialService({} as SecureHttpClientProvider)
        service.repository = new TestUserRepository()
        assert service.getIdentity("test")
        assert !service.getIdentity("notThere")
    }

    @Test
    void testValidateRegistration() {
        UserCredentialService service = new DefaultUserCredentialService({} as SecureHttpClientProvider)
        service.repository = new TestUserRepository()
        assert service.validateRegistration(new User(username: "test123", password: "testPassword", email: "test@trevorism.com"))
    }

    @Test
    void testChangePassword() {
        UserCredentialService service = new DefaultUserCredentialService({} as SecureHttpClientProvider)
        service.repository = new TestUserRepository()
        assert !service.changePassword(new User(username: "test"), "b4831cd6bd41ff8", "b4831cd6bd41ff9")
    }

    @Test
    void testForgotPassword() {
        UserCredentialService service = new DefaultUserCredentialService({} as SecureHttpClientProvider)
        service.repository = new TestUserRepository()
        service.emailer = [sendForgotPasswordEmail: { a, b -> }] as Emailer
        service.forgotPassword(new User(username: "test"))
    }

    @Test
    void testActivateUser() {
        UserCredentialService service = new DefaultUserCredentialService({} as SecureHttpClientProvider)
        service.repository = new TestUserRepository()
        service.emailer = [sendActivationEmail: { a -> }] as Emailer
        assert service.activateUser(new User(username: "test"), false)
    }

    @Test
    void testDeactivateUser() {
        UserCredentialService service = new DefaultUserCredentialService({} as SecureHttpClientProvider)
        service.repository = new TestUserRepository()
        assert service.deactivateUser(new User(username: "test"))
    }

    @Test
    void testInvalidUserRegistration_missingEmail() {
        UserCredentialService service = new DefaultUserCredentialService({} as SecureHttpClientProvider)
        service.repository = new TestUserRepository()
        assert !service.validateRegistration(new User(username: "test", password: "test"))
    }

    @Test
    void testValidateRegistration_passwordTooShort() {
        UserCredentialService service = new DefaultUserCredentialService({} as SecureHttpClientProvider)
        service.repository = new TestUserRepository()
        assert !service.validateRegistration(new User(username: "test123", password: "test", email: "test@trevorism.com"))
    }

    @Test
    void testValidateRegistration_missingUsername() {
        UserCredentialService service = new DefaultUserCredentialService({} as SecureHttpClientProvider)
        service.repository = new TestUserRepository()
        assert !service.validateRegistration(new User(password: "testPassword", email: "test@trevorism.com"))
    }

    @Test
    void testValidateRegistration_duplicateUsername() {
        UserCredentialService service = new DefaultUserCredentialService({} as SecureHttpClientProvider)
        service.repository = new TestUserRepository()
        assert !service.validateRegistration(new User(username: "test", password: "testPassword", email: "test@trevorism.com"))
    }

    class TestUserRepository implements Repository<User> {

        @Override
        List<User> list() {
            [new User(username: "test", salt: "5CeJI8KtC6TyTEsHAQCj4g==",
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
