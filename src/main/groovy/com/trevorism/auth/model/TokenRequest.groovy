package com.trevorism.auth.model

class TokenRequest {

    public static final String USER_TYPE = "user"
    public static final String APP_TYPE = "app"
    public static final String REFRESH_TYPE = "refresh"

    String id
    String password
    String type = APP_TYPE
    String audience
    String tenantGuid
}
