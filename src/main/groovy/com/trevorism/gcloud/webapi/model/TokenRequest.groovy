package com.trevorism.gcloud.webapi.model

class TokenRequest {

    public static final String USER_TYPE = "user"
    public static final String APP_TYPE = "app"

    String id
    String password
    String type = APP_TYPE
    String audience
}
