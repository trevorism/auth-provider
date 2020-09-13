package com.trevorism.gcloud.webapi.service

import com.trevorism.gcloud.webapi.model.Identity

interface TokenService {

    String issueToken(Identity identity, String audience)
    String issueRefreshToken(Identity identity)
}