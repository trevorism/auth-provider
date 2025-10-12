package com.trevorism.auth.bean

import com.trevorism.http.HttpClient
import com.trevorism.http.JsonHttpClient
import jakarta.inject.Named

@jakarta.inject.Singleton
@Named("injectableHttpClient")
class InjectableHttpClient extends JsonHttpClient implements HttpClient {
}
