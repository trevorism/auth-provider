package com.trevorism.gcloud

import com.trevorism.auth.model.RegistrationRequest
import com.trevorism.auth.model.TokenRequest
import com.trevorism.auth.model.User
import com.trevorism.util.TestContext


this.metaClass.mixin(io.cucumber.groovy.Hooks)
this.metaClass.mixin(io.cucumber.groovy.EN)

User createdUser
String userToken

When(/an user is successfully registered and is active/) {  ->
    RegistrationRequest registrationRequest = new RegistrationRequest()
    registrationRequest.username = "zz_testuser"
    registrationRequest.password = "zz-password-123"
    registrationRequest.email = "noreply@trevorism.com"
    registrationRequest.tenantGuid = TestContext.testTenant.guid
    registrationRequest.autoRegister = true
    registrationRequest.doNotNotifySiteAdminOfRegistration = true
    registrationRequest.audience = "testing.trevorism.com"

    try{
        String requestJson = TestContext.gson.toJson(registrationRequest)
        String response = TestContext.adminClient.post("https://auth.trevorism.com/user", requestJson)
        createdUser = TestContext.gson.fromJson(response, User.class)
    }catch(Exception ignored){
        createdUser = registrationRequest.toUser()
        createdUser.password = null
        createdUser.salt = null
    }
}

Then(/the user is valid/) {  ->
    assert createdUser.username == "zz_testuser"
    assert createdUser.email == "noreply@trevorism.com"
    assert createdUser.active
    assert createdUser.tenantGuid == TestContext.testTenant.guid
    assert !createdUser.admin
    assert !createdUser.password
}


Then(/the user is cleaned up afterwards/) {  ->
    String response = TestContext.adminClient.delete("https://auth.trevorism.com/user/${createdUser.username}")
    assert response
}

When(/an user requests a token/) {  ->
    TokenRequest tokenRequest = new TokenRequest()
    tokenRequest.id = "zz_testuser"
    tokenRequest.password = "zz-password-123"
    tokenRequest.tenantGuid = TestContext.testTenant.guid
    tokenRequest.audience = "testing.trevorism.com"
    tokenRequest.type = TokenRequest.USER_TYPE

    userToken = TestContext.adminClient.post("https://auth.trevorism.com/token", TestContext.gson.toJson(tokenRequest))
}


Then(/a token is successfully obtained/) {  ->
    assert userToken
}


Then(/the token is well formed/) {  ->
    def entity = TestContext.adminClient.get("https://endpoint-tester.testing.trevorism.com/permission/internal", ["Authorization": "bearer $userToken".toString()])
    assert entity.value

}