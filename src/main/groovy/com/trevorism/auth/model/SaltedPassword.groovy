package com.trevorism.auth.model

import groovy.transform.Immutable

@Immutable
class SaltedPassword {

    String salt
    String password
}