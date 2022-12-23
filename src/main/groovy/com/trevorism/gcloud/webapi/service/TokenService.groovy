package com.trevorism.gcloud.webapi.service

import com.trevorism.gcloud.webapi.model.Identity
import com.trevorism.secure.ClaimProperties

interface TokenService {

    String issueToken(Identity identity, String audience)
    String issueRefreshToken(Identity identity)

    ClaimProperties getClaimProperties(String bearerToken)
}