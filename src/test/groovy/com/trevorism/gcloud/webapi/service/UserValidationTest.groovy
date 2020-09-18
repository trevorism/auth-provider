package com.trevorism.gcloud.webapi.service

import com.trevorism.gcloud.webapi.model.User
import org.junit.Test

class UserValidationTest {

    @Test
    void testValidateUser() {
        UserCredentialService service = new DefaultUserCredentialService()
        service.repository = new DefaultUserCredentialServiceTest.TestUserRepository()
        assert !service.validateRegistration(null)
        assert !service.validateRegistration(new User())
        assert !service.validateRegistration(new User(username: "tester", password: "TESTer", email: "blah"))
        assert !service.validateRegistration(new User(username: "te", password: "TESTer", email: "test@trevorism.com"))
        assert !service.validateRegistration(new User(username: "tester", password: "TESTe", email: "test@trevorism.com"))
        assert service.validateRegistration(new User(username: "tester", password: "TESTer", email: "test@trevorism.com"))
    }

    @Test
    void testValidateCredentials() {
        UserCredentialService service = new DefaultUserCredentialService()
        service.repository = new DefaultUserCredentialServiceTest.TestUserRepository()

        assert !service.validateCredentials("test", "123")
    }
}
