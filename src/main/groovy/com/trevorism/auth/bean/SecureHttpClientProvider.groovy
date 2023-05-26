package com.trevorism.auth.bean

import com.trevorism.https.SecureHttpClient

interface SecureHttpClientProvider {

    SecureHttpClient getSecureHttpClient()
}
