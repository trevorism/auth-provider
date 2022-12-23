package com.trevorism.gcloud

import com.trevorism.http.headers.HeadersHttpClient
import com.trevorism.http.headers.HeadersJsonHttpClient
import com.trevorism.http.util.ResponseUtils
import com.trevorism.https.DefaultSecureHttpClient
import com.trevorism.secure.ClasspathBasedPropertiesProvider
import com.trevorism.secure.PropertiesProvider

this.metaClass.mixin(cucumber.api.groovy.Hooks)
this.metaClass.mixin(cucumber.api.groovy.EN)

def response = ""

When(/the endpoint tester internal endpoint is invoked/) { ->
    PropertiesProvider propertiesProvider = new ClasspathBasedPropertiesProvider()
    HeadersHttpClient jsonHttpClient = new HeadersJsonHttpClient()
    def token = propertiesProvider.getProperty("token")
    def entity = jsonHttpClient.get("https://endpoint-tester.testing.trevorism.com/secure/internal", ["Authorization": "bearer $token".toString()])
    response = ResponseUtils.getEntity(entity)
}

Then(/a response is returned successfully/) { ->
    assert response == "secure internal"
}
