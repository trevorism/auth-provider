package com.trevorism.auth.service

import com.trevorism.https.SecureHttpClient
import org.junit.jupiter.api.Test

class EmailerTest {

    @Test
    void testSendForgotPasswordEmail() {
        Emailer emailer = new Emailer([post: { x, y, z -> "{}" }] as SecureHttpClient)
        assert emailer.sendForgotPasswordEmail("trevorism@gmail.com", "12345678")
    }
}
