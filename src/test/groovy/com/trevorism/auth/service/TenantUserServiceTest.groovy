package com.trevorism.auth.service

import com.trevorism.auth.bean.TenantTokenSecureHttpClientProvider
import com.trevorism.auth.errors.AuthException
import com.trevorism.auth.model.RegistrationRequest
import com.trevorism.auth.model.TokenRequest
import com.trevorism.https.SecureHttpClient
import org.junit.jupiter.api.Test

import static org.junit.jupiter.api.Assertions.assertThrows

class TenantUserServiceTest {

    @Test
    void testValidateUser() {
        TenantUserService service = new TenantAwareUserService()
        def repository = new DefaultUserCredentialServiceTest.TestUserRepository()
        assertThrows(AuthException, () -> service.validateRegistration(repository, null))
        assertThrows(AuthException, () -> service.validateRegistration(repository, new RegistrationRequest()))
        assertThrows(AuthException, () -> service.validateRegistration(repository, new RegistrationRequest(username: "tester", password: "TESTer", email: "blah")))
        assertThrows(AuthException, () -> service.validateRegistration(repository, new RegistrationRequest(username: "te", password: "TESTer", email: "test@trevorism.com")))
        assertThrows(AuthException, () -> service.validateRegistration(repository, new RegistrationRequest(username: "tester", password: "TESTe", email: "test@trevorism.com")))
        assert service.validateRegistration(repository, new RegistrationRequest(username: "tester", password: "TESTer", email: "testz@trevorism.com"))
        assert service.validateRegistration(repository, new RegistrationRequest(username: "test123", password: "testPassword", email: "testx@trevorism.com"))
    }

    @Test
    void testValidateCredentials() {
        TenantUserService service = new TenantAwareUserService()
        service.generateTokenSecureHttpClientProvider = [getSecureHttpClient: { x, y -> {} as SecureHttpClient }] as TenantTokenSecureHttpClientProvider
        def repository = new DefaultUserCredentialServiceTest.TestUserRepository()
        service.metaClass.getUserByUsername = { repo, x -> repository.list()[0] }

        assert !service.validateCredentials(new TokenRequest(id: "test", password: "123"))
    }


    @Test
    void testValidateCredentials_InvalidPassword() {
        TenantUserService service = new TenantAwareUserService()
        service.generateTokenSecureHttpClientProvider = [getSecureHttpClient: { x, y -> {} as SecureHttpClient }] as TenantTokenSecureHttpClientProvider
        def repository = new DefaultUserCredentialServiceTest.TestUserRepository()
        service.metaClass.getUserByUsername = { repo, x -> repository.list()[0] }

        assert !service.validateCredentials(new TokenRequest(id: "test", password: "failPass"))
    }

    @Test
    void testValidateCredentials_MissingValues() {
        TenantUserService service = new TenantAwareUserService()
        assert !service.validateCredentials(new TokenRequest())
    }

}
