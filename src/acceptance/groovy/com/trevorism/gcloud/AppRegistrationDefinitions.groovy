package com.trevorism.gcloud

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.trevorism.https.AppClientSecureHttpClient
import com.trevorism.https.SecureHttpClient
import com.trevorism.util.JsonDateDeserializer

this.metaClass.mixin(io.cucumber.groovy.Hooks)
this.metaClass.mixin(io.cucumber.groovy.EN)

Gson gson = new GsonBuilder().registerTypeAdapter(Date.class,
        new JsonDateDeserializer()).setDateFormat("yyyy-MM-dd'T'HH:mm:ssZ").create()
SecureHttpClient secureHttpClient = new AppClientSecureHttpClient()
String listOfAllApps = ""


When(/the a list of apps is requested/) {  ->
    listOfAllApps = secureHttpClient.get("https://auth.trevorism.com/app")
}

Then(/the app list is successfully returned/) {  ->
    assert listOfAllApps
    assert listOfAllApps.contains("id")
    assert listOfAllApps.contains("clientId")
    assert listOfAllApps.contains("appName")
    assert listOfAllApps.contains("active")
    //You can only view the clientSecret when you update it specifically.
    assert !listOfAllApps.contains("clientSecret")

    List list = gson.fromJson(listOfAllApps, List.class)
    assert list.size() >= 1
}
