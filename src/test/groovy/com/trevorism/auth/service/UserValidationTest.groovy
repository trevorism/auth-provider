package com.trevorism.auth.service

import com.trevorism.auth.bean.SecureHttpClientProvider
import com.trevorism.auth.model.User
import org.junit.jupiter.api.Test

class UserValidationTest {

    @Test
    void testValidateUser() {
        UserCredentialService service = new DefaultUserCredentialService({} as SecureHttpClientProvider)
        service.repository = new DefaultUserCredentialServiceTest.TestUserRepository()
        assert !service.validateRegistration(null)
        assert !service.validateRegistration(new User())
        assert !service.validateRegistration(new User(username: "tester", password: "TESTer", email: "blah"))
        assert !service.validateRegistration(new User(username: "te", password: "TESTer", email: "test@trevorism.com"))
        assert !service.validateRegistration(new User(username: "tester", password: "TESTe", email: "test@trevorism.com"))
        assert service.validateRegistration(new User(username: "tester", password: "TESTer", email: "testz@trevorism.com"))
    }

    @Test
    void testValidateCredentials() {
        UserCredentialService service = new DefaultUserCredentialService({} as SecureHttpClientProvider)
        service.repository = new DefaultUserCredentialServiceTest.TestUserRepository()

        assert !service.validateCredentials("test", "123")
    }
}
