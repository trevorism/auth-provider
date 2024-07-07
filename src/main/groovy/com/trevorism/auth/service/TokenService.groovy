package com.trevorism.auth.service

import com.trevorism.auth.model.Identity
import com.trevorism.ClaimProperties
import com.trevorism.auth.model.InternalTokenRequest
import com.trevorism.auth.model.TokenRequest

interface TokenService {

    Identity getValidatedIdentity(TokenRequest tokenRequest)
    String issueToken(Identity identity, String audience)
    String issueRefreshToken(Identity identity)
    String issueInternalToken(Identity identity, String audience, String tenantId)
}