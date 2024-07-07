package com.trevorism.auth.model

interface Identity {

    String getId()
    String getIdentifer()
    boolean isActive()
    String getTenantGuid()
    String getPermissions()
    Date getDateCreated()
    Date getDateExpired()
}