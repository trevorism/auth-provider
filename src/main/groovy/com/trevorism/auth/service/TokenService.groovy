package com.trevorism.auth.service

import com.trevorism.auth.model.Identity
import com.trevorism.ClaimProperties

interface TokenService {

    String issueToken(Identity identity, String audience)
    String issueRefreshToken(Identity identity)

    ClaimProperties getClaimProperties(String bearerToken)
}