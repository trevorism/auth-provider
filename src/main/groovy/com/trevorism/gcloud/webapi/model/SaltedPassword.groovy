package com.trevorism.gcloud.webapi.model

import groovy.transform.Immutable

@Immutable
class SaltedPassword {

    String salt
    String password
}