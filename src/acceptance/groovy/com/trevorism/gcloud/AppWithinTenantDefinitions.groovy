package com.trevorism.gcloud

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.trevorism.auth.model.App
import com.trevorism.auth.model.User
import com.trevorism.http.HttpClient
import com.trevorism.http.JsonHttpClient
import com.trevorism.https.AppClientSecureHttpClient
import com.trevorism.https.SecureHttpClient
import com.trevorism.util.AdminUserSecureHttpClient
import com.trevorism.util.DecryptionRequest
import com.trevorism.util.JsonDateDeserializer
import com.trevorism.util.Tenant

this.metaClass.mixin(io.cucumber.groovy.Hooks)
this.metaClass.mixin(io.cucumber.groovy.EN)

Gson gson = new GsonBuilder().registerTypeAdapter(Date.class, new JsonDateDeserializer()).setDateFormat("yyyy-MM-dd'T'HH:mm:ssZ").create()
HttpClient httpClient = new JsonHttpClient()
SecureHttpClient appClientSecureHttpClient = new AppClientSecureHttpClient()
SecureHttpClient adminClient
Tenant testTenant
App createdApp

Given(/the auth test tenant is registered/) { ->
    String jsonArr = appClientSecureHttpClient.get("https://tenant.auth.trevorism.com/tenant")
    def list = gson.fromJson(jsonArr, List.class)
    testTenant = list.find { it.name == "auth_acceptance_tests" } as Tenant
    assert testTenant
}

Given(/a auth test tenant admin user is registered/) { ->
    DecryptionRequest decryptionRequest = new DecryptionRequest(payload: "+wSPLFuzP229Pf9a2GYf+rnJf9H/hNNC", key: appClientSecureHttpClient.obtainTokenStrategy.clientId)
    String password = appClientSecureHttpClient.post("https://encryption.project.trevorism.com/crypt/decryption", gson.toJson(decryptionRequest))
    adminClient = new AdminUserSecureHttpClient(httpClient, password, testTenant.guid, "testing.trevorism.com")
    String tenantAdminJson = adminClient.get("https://auth.trevorism.com/user/me")
    User tenantAdminUser = gson.fromJson(tenantAdminJson, User.class)
    assert tenantAdminUser
    assert tenantAdminUser.active
    assert tenantAdminUser.admin
    assert tenantAdminUser.tenantGuid == testTenant.guid
}

When(/an app is registered with a clientId/) { ->
    App app = new App(appName: "zz_TestApp", tenantGuid: testTenant.guid)
    String json = gson.toJson(app)
    //String responseJson = adminClient.post("https://auth.trevorism.com/app", json)
    //createdApp = gson.fromJson(responseJson, App.class)
}

Then(/an app is successfully registered with a clientId/) { ->
    //assert createdApp
    //assert createdApp.id
    //assert createdApp.clientId
    //assert createdApp.appName == "zz_TestApp"
    //assert createdApp.active
    //assert createdApp.tenantGuid == testTenant.guid
    //assert !createdApp.clientSecret
}


Then(/the app is cleaned up afterwards/) { ->
    //adminClient.delete("https://auth.trevorism.com/app/${createdApp.id}")
}

When(/a client secret is requested for the registered app/) { ->

}


Then(/a client secret is successfully generated for the app/) { ->

}


When(/a client secret is requested to be updated for the registered app/) { ->

}


Then(/a client secret is successfully updated for the app/) { ->

}