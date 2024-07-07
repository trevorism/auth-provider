package com.trevorism.gcloud

import com.trevorism.ClasspathBasedPropertiesProvider
import com.trevorism.PropertiesProvider
import com.trevorism.http.HttpClient
import com.trevorism.http.JsonHttpClient
import com.trevorism.https.AppClientSecureHttpClient
import com.trevorism.https.SecureHttpClient


this.metaClass.mixin(io.cucumber.groovy.Hooks)
this.metaClass.mixin(io.cucumber.groovy.EN)

def response = ""

When(/the endpoint tester internal endpoint is invoked/) { ->
    PropertiesProvider propertiesProvider = new ClasspathBasedPropertiesProvider()
    HttpClient jsonHttpClient = new JsonHttpClient()
    def token = propertiesProvider.getProperty("token")
    def entity = jsonHttpClient.get("https://endpoint-tester.testing.trevorism.com/permission/internal", ["Authorization": "bearer $token".toString()])
    response = entity.value
}

When(/the endpoint tester secure endpoint is invoked/) {  ->
    SecureHttpClient secureHttpClient = new AppClientSecureHttpClient()
    response = secureHttpClient.get("https://endpoint-tester.testing.trevorism.com/secure/json")
}

Then(/a response of {string} is returned successfully/) { String string ->
    assert response == string
}