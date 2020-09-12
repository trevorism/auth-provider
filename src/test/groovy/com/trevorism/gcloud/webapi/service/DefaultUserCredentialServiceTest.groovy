package com.trevorism.gcloud.webapi.service

import com.trevorism.data.Repository
import com.trevorism.gcloud.webapi.model.User
import com.trevorism.secure.Roles
import org.junit.Test

class DefaultUserCredentialServiceTest {

    @Test
    void testGetUser() {
        UserCredentialService service = new DefaultUserCredentialService()
        service.repository = new TestUserRepository()
        assert service.getUser("5154038974775296")
        assert !service.getUser("6")
    }

    @Test
    void testDeleteUser() {
        UserCredentialService service = new DefaultUserCredentialService()
        service.repository = new TestUserRepository()
        assert service.getUser("5154038974775296")
        assert !service.getUser("6")
    }

    @Test
    void testListUsers() {
        UserCredentialService service = new DefaultUserCredentialService()
        service.repository = new TestUserRepository()
        assert service.listUsers()
    }

    @Test
    void testRegisterUser() {
        UserCredentialService service = new DefaultUserCredentialService()
        service.repository = new TestUserRepository()
        assert service.registerUser(new User(username: "testUsername", email: "test@trevorism.com", password: "testPass"))
    }

    @Test
    void testValidateCredentials() {
        UserCredentialService service = new DefaultUserCredentialService()
        service.repository = new TestUserRepository()
        assert !service.validateCredentials("test", "failPass")
    }

    @Test
    void testGetIdentity() {
        UserCredentialService service = new DefaultUserCredentialService()
        service.repository = new TestUserRepository()
        assert service.getIdentity("test")
        assert !service.getIdentity("notThere")
    }

    @Test
    void testValidateRegistration() {
        UserCredentialService service = new DefaultUserCredentialService()
        service.repository = new TestUserRepository()
        assert service.validateRegistration(new User(username: "test123", password: "testPassword", email: "test@trevorism.com"))
    }

    @Test
    void testChangePassword() {
        UserCredentialService service = new DefaultUserCredentialService()
        service.repository = new TestUserRepository()
        assert !service.changePassword(new User(username: "test"), "b4831cd6bd41ff8", "b4831cd6bd41ff9")
    }

    @Test
    void testForgotPassword() {
        UserCredentialService service = new DefaultUserCredentialService()
        service.repository = new TestUserRepository()
        service.emailer = [sendForgotPasswordEmail: {a,b -> }] as Emailer
        service.forgotPassword(new User(username: "test"))
    }

    @Test
    void testActivateUser() {
        UserCredentialService service = new DefaultUserCredentialService()
        service.repository = new TestUserRepository()
        assert service.activateUser(new User(username: "test"), false)
    }


    class TestUserRepository implements Repository<User>{

        @Override
        List<User> list() {
            return list(null)
        }

        @Override
        List<User> list(String s) {
            [new User(username: "test", salt: "123", password: "123")]
        }

        @Override
        User get(String s) {
            return get(s, null)
        }

        @Override
        User get(String s, String s1) {
            if(s == "5154038974775296")
                return new User()
            return null
        }

        @Override
        User create(User user) {
            return create(user, null)
        }

        @Override
        User create(User user, String s) {
            return user
        }

        @Override
        User update(String s, User user) {
            return update(s, user, null)
        }

        @Override
        User update(String s, User user, String s1) {
            return user
        }

        @Override
        User delete(String s) {
            delete(s, null)
        }

        @Override
        User delete(String s, String s1) {
            if(s == "5154038974775296")
                return new User()
            return null
        }

        @Override
        void ping() {

        }
    }
}
