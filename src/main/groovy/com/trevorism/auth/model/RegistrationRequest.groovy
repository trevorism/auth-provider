package com.trevorism.auth.model

class RegistrationRequest {

    String username
    String password
    String email
    String tenantGuid
    boolean autoRegister = false
    boolean doNotNotifySiteAdminOfRegistration = false
    String audience

    User toUser(){
        User user = new User()
        user.username = username
        user.password = password
        user.email = email
        user.tenantGuid = tenantGuid
        user.active = autoRegister
        return user
    }
}
