package com.trevorism.gcloud.webapi.controller

import org.junit.Test

/**
 * @author tbrooks
 */
class AuthorizeControllerTest {

    @Test
    void testAuthorize() {
        AuthorizeController authorizeController = new AuthorizeController()
        authorizeController.authorize()

    }
}
