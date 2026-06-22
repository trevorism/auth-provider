package com.trevorism.auth.model

class ActivationRequest {
    String username
    String tenantGuid
    boolean isAdmin = false
    boolean doNotSendWelcomeEmail = true
}
