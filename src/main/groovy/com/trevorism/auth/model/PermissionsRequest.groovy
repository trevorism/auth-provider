package com.trevorism.auth.model

import groovy.transform.ToString

@ToString
class PermissionsRequest {

    String username
    String tenantGuid
    String permissions
}
