package com.trevorism.auth.model

class HandoffCode {
    String id
    String secretHash
    String redirectUri
    String subject
    String accessToken
    String refreshToken
    Date dateCreated
    Date dateExpired
}
