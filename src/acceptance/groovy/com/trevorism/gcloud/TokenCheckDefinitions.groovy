package com.trevorism.gcloud

import com.trevorism.ClasspathBasedPropertiesProvider
import com.trevorism.PropertiesProvider
import com.trevorism.http.HttpClient
import com.trevorism.http.JsonHttpClient



this.metaClass.mixin(io.cucumber.groovy.Hooks)
this.metaClass.mixin(io.cucumber.groovy.EN)

def response = ""

When(/the endpoint tester internal endpoint is invoked/) { ->
    PropertiesProvider propertiesProvider = new ClasspathBasedPropertiesProvider()
    HttpClient jsonHttpClient = new JsonHttpClient()
    def token = propertiesProvider.getProperty("token")
    def entity = jsonHttpClient.get("https://endpoint-tester.testing.trevorism.com/secure/internal", ["Authorization": "bearer $token".toString()])
    response = entity.value
}

Then(/a response is returned successfully/) { ->
    assert response == "secure internal"
}
