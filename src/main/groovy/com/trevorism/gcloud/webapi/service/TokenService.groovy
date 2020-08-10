package com.trevorism.gcloud.webapi.service

import com.trevorism.gcloud.webapi.model.User

interface TokenService {

    String issueToken(User user)
}