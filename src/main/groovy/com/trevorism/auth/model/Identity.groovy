package com.trevorism.auth.model

interface Identity {

    String getId()
    String getIdentifer()
    boolean isActive()
    String getTenantGuid()
    Date getDateCreated()
    Date getDateExpired()
}