package com.trevorism.gcloud.webapi.service

import com.trevorism.gcloud.webapi.model.Identity
import com.trevorism.gcloud.webapi.model.TokenRequest

interface TokenService {

    String issueToken(Identity identity, TokenRequest tokenRequest)
}