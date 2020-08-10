package com.trevorism.gcloud.webapi.model

import groovy.transform.ToString

@ToString
class User {

    String id
    String username
    String email
    String image

    String password
    String salt
}
