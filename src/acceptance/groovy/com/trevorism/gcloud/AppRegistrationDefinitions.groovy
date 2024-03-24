package com.trevorism.gcloud

import com.google.gson.Gson
import com.trevorism.https.AppClientSecureHttpClient
import com.trevorism.https.SecureHttpClient

this.metaClass.mixin(io.cucumber.groovy.Hooks)
this.metaClass.mixin(io.cucumber.groovy.EN)

SecureHttpClient secureHttpClient = new AppClientSecureHttpClient()
String listOfAllApps = ""

Given(/an app is registered with a clientId/) {  ->

}


Then(/an app is succesfully registered with a clientId/) {  ->

}


Then(/the app is cleaned up afterwards/) {  ->

}



When(/a client secret is requested for the registered app/) {  ->

}


Then(/a client secret is successfully generated for the app/) {  ->

}


When(/a client secret is requested to be updated for the registered app/) {  ->

}


Then(/a client secret is successfully updated for the app/) {  ->

}


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

    Gson gson = new Gson()
    List list = gson.fromJson(listOfAllApps, List.class)
    assert list.size() >= 1
}
