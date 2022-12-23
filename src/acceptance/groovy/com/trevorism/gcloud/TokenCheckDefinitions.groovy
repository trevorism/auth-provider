package com.trevorism.gcloud

import com.trevorism.http.headers.HeadersHttpClient
import com.trevorism.http.headers.HeadersJsonHttpClient
import com.trevorism.http.util.ResponseUtils
import com.trevorism.https.DefaultSecureHttpClient
import com.trevorism.secure.ClasspathBasedPropertiesProvider
import com.trevorism.secure.PropertiesProvider

this.metaClass.mixin(cucumber.api.groovy.Hooks)
this.metaClass.mixin(cucumber.api.groovy.EN)

PropertiesProvider propertiesProvider = new ClasspathBasedPropertiesProvider()
HeadersHttpClient jsonHttpClient = new HeadersJsonHttpClient()
def response = ""
def token = propertiesProvider.getProperty("token")

When(/the endpoint tester internal endpoint is invoked/) { ->
    def entity = jsonHttpClient.get("https://endpoint-tester.testing.trevorism.com/secure/internal", ["Authorization": "bearer $token".toString()])
    response = ResponseUtils.getEntity(entity)
}

When(/a refresh token is requested/) {  ->
    token = new DefaultSecureHttpClient().post("https://auth.trevorism.com/token/refresh", "{}")
}

Then(/a response is returned successfully/) { ->
    assert response == "secure internal"
}
