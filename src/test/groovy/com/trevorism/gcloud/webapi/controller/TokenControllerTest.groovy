package com.trevorism.gcloud.webapi.controller

import com.trevorism.gcloud.webapi.model.Identity
import com.trevorism.gcloud.webapi.model.TokenRequest
import com.trevorism.gcloud.webapi.model.User
import com.trevorism.gcloud.webapi.service.AppRegistrationService
import com.trevorism.gcloud.webapi.service.CredentialValidator
import com.trevorism.gcloud.webapi.service.TokenService
import com.trevorism.gcloud.webapi.service.UserCredentialService
import com.trevorism.secure.ClaimProperties
import com.trevorism.secure.ClaimsProvider
import org.junit.Test

import javax.ws.rs.BadRequestException
import javax.ws.rs.core.HttpHeaders

class TokenControllerTest {

    private static final String FAKE_TOKEN = "eyzz.asdf.gdsfg"

    @Test
    void testGetBearerToken() {
        String token = TokenController.getBearerToken(createHeaders())
        assert "eyzz.asdf.gdsfg" == token
    }

    @Test
    void testRegenerateToken() {
        ClaimsProvider.metaClass.'static'.getClaims = {String str -> new ClaimProperties()}
        TokenController tokenController = new TokenController()
        Identity identity = new User()
        tokenController.userCredentialService = [getIdentity:{ sub ->
            identity.username = sub
            return identity
        }] as UserCredentialService
        tokenController.tokenService = [issueToken: {id, aud -> FAKE_TOKEN}] as TokenService

        assert FAKE_TOKEN == tokenController.regenerateToken(createHeaders())
    }

    @Test(expected = BadRequestException)
    void testBadTokenRequest() {
        TokenController tokenController = new TokenController()
        assert !tokenController.token(new TokenRequest())
    }

    @Test(expected = BadRequestException)
    void testBadTokenUserRequest() {
        TokenController tokenController = new TokenController()
        assert !tokenController.token(new TokenRequest(type: TokenRequest.USER_TYPE))
    }

    @Test
    void testGetUserToken() {
        TokenController tokenController = new TokenController()
        tokenController.userCredentialService = [validateCredentials: {u,p -> true}, getIdentity: {new User(username: "test")}] as UserCredentialService
        tokenController.tokenService = [issueToken: {u,aud -> FAKE_TOKEN}] as TokenService
        assert FAKE_TOKEN == tokenController.token(new TokenRequest(id:"username", password: "password", type: TokenRequest.USER_TYPE))
    }

    @Test
    void testGetAppToken() {
        TokenController tokenController = new TokenController()
        tokenController.appRegistrationService = [validateCredentials: {u,p -> true}, getIdentity: {new User(username: "test")}] as AppRegistrationService
        tokenController.tokenService = [issueToken: {u,aud -> FAKE_TOKEN}] as TokenService
        assert FAKE_TOKEN == tokenController.token(new TokenRequest(id:"username", password: "password", type: TokenRequest.APP_TYPE))
    }

    private HttpHeaders createHeaders() {
        def headers = ["getHeaderString": { str -> "bearer ${FAKE_TOKEN}".toString() }] as HttpHeaders
        return headers
    }
}
