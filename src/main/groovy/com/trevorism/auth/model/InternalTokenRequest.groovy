package com.trevorism.auth.model

class InternalTokenRequest {

    Date expiration
    String subject
    String audience
    String tenantId

}
