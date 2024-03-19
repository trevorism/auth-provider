package com.trevorism.auth.model

class ForgotPasswordRequest {
    String username
    String tenantGuid
    String audience = "trevorism.com"
}
