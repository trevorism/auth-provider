package com.trevorism.gcloud

import com.trevorism.http.JsonHttpClient
import com.trevorism.https.AppClientSecureHttpClient
import com.trevorism.https.SecureHttpClient
import com.trevorism.util.TestContext

this.metaClass.mixin(io.cucumber.groovy.Hooks)
this.metaClass.mixin(io.cucumber.groovy.EN)

SecureHttpClient secureHttpClient = new AppClientSecureHttpClient()
JsonHttpClient anonymousClient = new JsonHttpClient()
String baseUrl = System.getenv("ACCEPTANCE_BASE_URL") ?: "https://auth.trevorism.com"

String handoffCode
String handoffResponse
Exception handoffFailure
String redeemResponse
Exception redeemFailure

When("a handoff code is requested for {string}") { String redirectUri ->
    handoffFailure = null
    handoffResponse = null
    try {
        handoffResponse = secureHttpClient.post("${baseUrl}/token/handoff", TestContext.gson.toJson([redirectUri: redirectUri]))
        handoffCode = TestContext.gson.fromJson(handoffResponse, Map).code
    } catch (Exception e) {
        handoffFailure = e
    }
}

Then("a handoff code is returned") { ->
    assert !handoffFailure
    assert handoffCode
    assert handoffCode.contains(".")
}

Then("the handoff request is rejected") { ->
    assert handoffFailure
}

When("the handoff code is redeemed at {string}") { String redirectUri ->
    redeemFailure = null
    redeemResponse = null
    try {
        redeemResponse = anonymousClient.post("${baseUrl}/token/handoff/redeem", TestContext.gson.toJson([code: handoffCode, redirectUri: redirectUri]))
    } catch (Exception e) {
        redeemFailure = e
    }
}

Then("the caller's access token is returned") { ->
    assert !redeemFailure
    Map tokens = TestContext.gson.fromJson(redeemResponse, Map)
    assert tokens.accessToken
    assert tokens.accessToken.split(/\./).length == 3
}

Then("the handoff redeem is rejected") { ->
    assert redeemFailure
}

Then("the redirect URI {string} is allowed") { String uri ->
    String json = secureHttpClient.get("${baseUrl}/token/handoff/allowed?uri=${URLEncoder.encode(uri, 'UTF-8')}")
    assert TestContext.gson.fromJson(json, Map).allowed == true
}

Then("the redirect URI {string} is not allowed") { String uri ->
    String json = secureHttpClient.get("${baseUrl}/token/handoff/allowed?uri=${URLEncoder.encode(uri, 'UTF-8')}")
    assert TestContext.gson.fromJson(json, Map).allowed == false
}
