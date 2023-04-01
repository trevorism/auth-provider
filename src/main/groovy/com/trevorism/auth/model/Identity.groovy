package com.trevorism.auth.model

interface Identity {

    String getId()
    String getIdentifer()
    boolean isActive()
    Date getDateCreated()
    Date getDateExpired()
}