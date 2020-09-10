package com.trevorism.gcloud.webapi.model

import groovy.transform.ToString

@ToString
class App implements Identity{

    String id
    String appName
    String clientId
    String clientSecret
    String salt

    List<String> replyUrls
    List<String> logoutUrls

    boolean active
    Date dateCreated
    Date dateExpired

    @Override
    String getIdentifer() {
        return clientId
    }
}
