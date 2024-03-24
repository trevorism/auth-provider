package com.trevorism.auth.service

import com.trevorism.EmailClient
import com.trevorism.auth.bean.TenantTokenSecureHttpClientProvider
import com.trevorism.https.SecureHttpClient
import org.junit.jupiter.api.Test

class EmailerTest {

    @Test
    void testSendForgotPasswordEmail() {
        Emailer emailer = new Emailer([getSecureHttpClient: { x,y -> {} as SecureHttpClient }] as TenantTokenSecureHttpClientProvider)
        emailer.emailClient = new EmailClient([post: { x, y -> "{}" }] as SecureHttpClient)
        assert emailer.sendForgotPasswordEmail("trevorism@gmail.com", "username", "12345678", "trevorism.com")
    }
}
