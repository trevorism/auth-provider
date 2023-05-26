package com.trevorism.auth.bean

import com.trevorism.https.InternalTokenSecureHttpClient
import com.trevorism.https.SecureHttpClient

@jakarta.inject.Singleton
class InternalTokenSecureHttpClientProvider implements SecureHttpClientProvider {

    private SecureHttpClient secureHttpClient = new InternalTokenSecureHttpClient()

    SecureHttpClient getSecureHttpClient() {
        return secureHttpClient
    }
}
