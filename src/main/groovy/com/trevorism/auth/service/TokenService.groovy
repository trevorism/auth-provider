package com.trevorism.auth.service

import com.trevorism.auth.model.Identity
import com.trevorism.ClaimProperties
import com.trevorism.auth.model.InternalTokenRequest

interface TokenService {

    String issueToken(Identity identity, String audience)
    String issueRefreshToken(Identity identity)

    ClaimProperties getClaimProperties(String bearerToken)

    String issueInternalToken(InternalTokenRequest internalTokenRequest)
}