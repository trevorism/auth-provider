package com.trevorism.auth.service

interface RedirectUriPolicy {

    boolean isAllowed(String redirectUri)
}
