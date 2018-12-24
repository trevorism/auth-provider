package com.trevorism.gcloud.webapi.controller


import com.trevorism.http.BlankHttpClient

import javax.ws.rs.GET
import javax.ws.rs.Path

/**
 * @author tbrooks
 *
 */
@Path("/authorize")
class AuthorizeController {

    @GET
    void authorize() {
        BlankHttpClient httpClient = new BlankHttpClient()
        String redirectUrl = URLEncoder.encode("https://auth-provider-dot-trevorism-auth.appspot.com/","UTF-8")
        println redirectUrl

        String baseUrl = "https://login.microsoftonline.com/903c4576-e96b-4e70-a6bd-3b78d8c3ad37/oauth2/authorize" +
                "?client_id=3cf65416-738e-4566-9f8a-105baa20e36e" +
                "&response_type=code" +
                "&redirect_uri=${redirectUrl}" +
                "&response_mode=query"

        println baseUrl
        //println httpClient.get(baseUrl)
    }

}
