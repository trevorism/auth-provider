package com.trevorism.gcloud.webapi.controller

import org.junit.Test

/**
 * @author tbrooks
 */
class CredentialsControllerTest {

    @Test
    void testAuthorize() {
        CredentialsController authorizeController = new CredentialsController()
        authorizeController.authorize()

    }
}
