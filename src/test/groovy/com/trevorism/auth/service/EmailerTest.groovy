package com.trevorism.auth.service

import com.trevorism.EmailClient
import com.trevorism.https.SecureHttpClient
import org.junit.jupiter.api.Test

class EmailerTest {

    @Test
    void testSendForgotPasswordEmail() {
        Emailer emailer = new Emailer()
        emailer.emailClient = new EmailClient([post: { x, y -> "{}" }] as SecureHttpClient)
        assert emailer.sendForgotPasswordEmail("trevorism@gmail.com", "12345678")
    }
}
