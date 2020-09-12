package com.trevorism.gcloud.webapi.model

interface Identity {

    String getId()
    String getIdentifer()
    boolean isActive()
    Date getDateCreated()
    Date getDateExpired()
}