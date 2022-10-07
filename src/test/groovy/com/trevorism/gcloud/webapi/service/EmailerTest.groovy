package com.trevorism.gcloud.webapi.service

import com.trevorism.https.SecureHttpClient
import com.trevorism.model.Email
import org.junit.Test

class EmailerTest {

    @Test
    void testSendForgotPasswordEmail() {
        Emailer emailer = new Emailer([post: { x, y, z -> "{}" }] as SecureHttpClient)
        assert emailer.sendForgotPasswordEmail("trevorism@gmail.com", "12345678")
    }
}
