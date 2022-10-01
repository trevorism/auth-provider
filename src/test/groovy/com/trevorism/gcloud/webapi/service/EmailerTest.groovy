package com.trevorism.gcloud.webapi.service

import com.trevorism.https.SecureHttpClient
import org.junit.Test

class EmailerTest {

    @Test
    void testSendForgotPasswordEmail() {
        Emailer emailer = new Emailer([post: { x, y, z -> "true" }] as SecureHttpClient)
        assert emailer.sendForgotPasswordEmail("trevorism@gmail.com", "12345678")
    }
}
