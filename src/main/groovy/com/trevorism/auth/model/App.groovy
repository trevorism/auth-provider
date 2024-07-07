package com.trevorism.auth.model

import groovy.transform.ToString

@ToString
class App implements Identity{

    static App NULL_APP = new App()

    String id
    String appName
    String clientId
    String clientSecret
    String salt

    List<String> replyUrls
    List<String> logoutUrls

    String tenantGuid
    String permissions

    boolean active
    Date dateCreated
    Date dateExpired

    @Override
    String getIdentifer() {
        return clientId
    }

}
