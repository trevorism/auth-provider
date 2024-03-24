package com.trevorism.auth.bean

import com.trevorism.https.SecureHttpClient

interface TenantTokenSecureHttpClientProvider {

    SecureHttpClient getSecureHttpClient(String tenantId, String audience)
}
