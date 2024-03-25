package com.trevorism.gcloud

import com.trevorism.auth.model.App
import com.trevorism.auth.model.User
import com.trevorism.http.HttpClient
import com.trevorism.http.JsonHttpClient
import com.trevorism.https.AppClientSecureHttpClient
import com.trevorism.https.SecureHttpClient
import com.trevorism.util.AdminUserSecureHttpClient
import com.trevorism.util.DecryptionRequest
import com.trevorism.util.Tenant
import com.trevorism.util.TestContext

this.metaClass.mixin(io.cucumber.groovy.Hooks)
this.metaClass.mixin(io.cucumber.groovy.EN)

HttpClient httpClient = new JsonHttpClient()
SecureHttpClient appClientSecureHttpClient = new AppClientSecureHttpClient()
App createdApp
String clientSecret
String clientSecret2

Given(/the auth test tenant is registered/) { ->
    String jsonArr = appClientSecureHttpClient.get("https://tenant.auth.trevorism.com/tenant")
    def list = TestContext.gson.fromJson(jsonArr, List.class)
    TestContext.testTenant = list.find { it.name == "auth_acceptance_tests" } as Tenant
    assert TestContext.testTenant
}

Given(/an auth test tenant admin user is registered/) { ->
    DecryptionRequest decryptionRequest = new DecryptionRequest(payload: "+wSPLFuzP229Pf9a2GYf+rnJf9H/hNNC", key: appClientSecureHttpClient.obtainTokenStrategy.clientId)
    String password = appClientSecureHttpClient.post("https://encryption.project.trevorism.com/crypt/decryption", TestContext.gson.toJson(decryptionRequest))
    TestContext.adminClient = new AdminUserSecureHttpClient(httpClient, password, TestContext.testTenant.guid, "testing.trevorism.com")
    String tenantAdminJson = TestContext.adminClient.get("https://auth.trevorism.com/user/me")
    User tenantAdminUser = TestContext.gson.fromJson(tenantAdminJson, User.class)
    assert tenantAdminUser
    assert tenantAdminUser.active
    assert tenantAdminUser.admin
    assert tenantAdminUser.tenantGuid == TestContext.testTenant.guid
}

When(/an app is registered with a clientId/) { ->
    App app = new App(appName: "zz_TestApp", tenantGuid: TestContext.testTenant.guid)
    String json = TestContext.gson.toJson(app)
    String responseJson = TestContext.adminClient.post("https://auth.trevorism.com/app", json)
    createdApp = TestContext.gson.fromJson(responseJson, App.class)
}

Then(/an app is successfully registered with a clientId/) { ->
    assert createdApp
    assert createdApp.id
    assert createdApp.clientId
    assert createdApp.appName == "zz_TestApp"
    assert createdApp.active
    assert createdApp.tenantGuid == TestContext.testTenant.guid
    assert !createdApp.clientSecret
}


Then(/the app is cleaned up afterwards/) { ->
    TestContext.adminClient.delete("https://auth.trevorism.com/app/${createdApp.id}")
}

When(/a client secret is requested for the registered app/) { ->
    clientSecret = TestContext.adminClient.put("https://auth.trevorism.com/app/${createdApp.clientId}/secret", "{}")
}


Then(/a client secret is successfully generated for the app/) { ->
    assert clientSecret
}


When(/a client secret is requested to be updated for the registered app/) { ->
    clientSecret2 = TestContext.adminClient.put("https://auth.trevorism.com/app/${createdApp.clientId}/secret", "{}")
}


Then(/a client secret is successfully updated for the app/) { ->
    assert clientSecret2
    assert clientSecret != clientSecret2
}