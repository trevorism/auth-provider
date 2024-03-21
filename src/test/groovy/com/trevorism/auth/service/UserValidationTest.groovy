package com.trevorism.auth.service

import com.trevorism.auth.model.RegistrationRequest
import com.trevorism.auth.model.TokenRequest
import com.trevorism.https.SecureHttpClient
import org.junit.jupiter.api.Test

class UserValidationTest {

    @Test
    void testValidateUser() {
        UserCredentialService service = new DefaultUserCredentialService({} as SecureHttpClient)
        service.repository = new DefaultUserCredentialServiceTest.TestUserRepository()
        assert !service.validateRegistration(null)
        assert !service.validateRegistration(new RegistrationRequest())
        assert !service.validateRegistration(new RegistrationRequest(username: "tester", password: "TESTer", email: "blah"))
        assert !service.validateRegistration(new RegistrationRequest(username: "te", password: "TESTer", email: "test@trevorism.com"))
        assert !service.validateRegistration(new RegistrationRequest(username: "tester", password: "TESTe", email: "test@trevorism.com"))
        assert service.validateRegistration(new RegistrationRequest(username: "tester", password: "TESTer", email: "testz@trevorism.com"))
    }

    @Test
    void testValidateCredentials() {
        UserCredentialService service = new DefaultUserCredentialService({} as SecureHttpClient)
        service.repository = new DefaultUserCredentialServiceTest.TestUserRepository()

        assert !service.validateCredentials(new TokenRequest(id:"test", password:"123"))
    }
}
