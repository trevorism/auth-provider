package com.trevorism.auth.model

class ChangePasswordRequest {
    String username
    String currentPassword
    String desiredPassword
    String tenantGuid
    String audience = "trevorism.com"
}
