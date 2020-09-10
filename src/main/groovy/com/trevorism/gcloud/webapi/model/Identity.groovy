package com.trevorism.gcloud.webapi.model

interface Identity {

    String getIdentifer()
    boolean isActive()
    Date getDateCreated()
    Date getDateExpired()
}