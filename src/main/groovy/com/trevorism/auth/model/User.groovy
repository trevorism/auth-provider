package com.trevorism.auth.model

import groovy.transform.ToString

@ToString
class User implements Identity{

    String id
    String username
    String email
    String image

    String password
    String salt

    boolean admin
    boolean active

    String tenantGuid
    String permissions

    Date dateCreated
    Date dateExpired

    @Override
    String getIdentifer() {
        return username
    }
}
