package com.trevorism.util

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.trevorism.https.SecureHttpClient

class TestContext {
    static SecureHttpClient adminClient
    static Tenant testTenant
    static Gson gson = new GsonBuilder().registerTypeAdapter(Date.class,
            new JsonDateDeserializer()).setDateFormat("yyyy-MM-dd'T'HH:mm:ssZ").create()
}
