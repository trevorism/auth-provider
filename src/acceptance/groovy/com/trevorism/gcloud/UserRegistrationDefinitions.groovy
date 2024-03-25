package com.trevorism.gcloud


import com.trevorism.https.AppClientSecureHttpClient
import com.trevorism.https.SecureHttpClient

import com.trevorism.util.TestContext

this.metaClass.mixin(io.cucumber.groovy.Hooks)
this.metaClass.mixin(io.cucumber.groovy.EN)


SecureHttpClient secureHttpClient = new AppClientSecureHttpClient()
String listOfAllUsers = ""

When(/the a list of users is requested/) {  ->
    listOfAllUsers = secureHttpClient.get("https://auth.trevorism.com/user")
}

Then(/the user list is successfully returned/) {  ->
    assert listOfAllUsers
    assert listOfAllUsers.contains("id")
    assert listOfAllUsers.contains("username")
    assert listOfAllUsers.contains("active")
    //You can only view the clientSecret when you update it specifically.
    assert !listOfAllUsers.contains("password")

    List list = TestContext.gson.fromJson(listOfAllUsers, List.class)
    assert list.size() >= 1
}