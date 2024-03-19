package com.trevorism.auth.model

class ActivationRequest {
    String username
    String tenantGuid
    boolean isAdmin
    boolean doNotSendWelcomeEmail
}
