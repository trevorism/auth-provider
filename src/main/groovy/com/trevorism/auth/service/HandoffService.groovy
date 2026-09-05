package com.trevorism.auth.service

import com.trevorism.auth.model.HandoffResponse
import com.trevorism.auth.model.HandoffTokens
import io.micronaut.security.authentication.Authentication

interface HandoffService {

    HandoffResponse createCode(Authentication authentication, String accessToken, String refreshToken, String redirectUri)

    HandoffTokens redeemCode(String code, String redirectUri)
}
