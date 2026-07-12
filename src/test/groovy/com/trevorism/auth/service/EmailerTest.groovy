package com.trevorism.auth.service

import com.trevorism.EmailClient
import com.trevorism.auth.bean.TenantTokenSecureHttpClientProvider
import com.trevorism.auth.model.Tenant
import com.trevorism.data.Repository
import com.trevorism.https.SecureHttpClient
import org.junit.jupiter.api.Test

class EmailerTest {

    @Test
    void testSendForgotPasswordEmail() {
        Emailer emailer = new Emailer([getSecureHttpClient: { x,y -> {} as SecureHttpClient }] as TenantTokenSecureHttpClientProvider)
        emailer.emailClient = new EmailClient([post: { x, y -> "{}" }] as SecureHttpClient)
        assert emailer.sendForgotPasswordEmail("trevorism@gmail.com", "username", "12345678", "trevorism.com")
    }

    @Test
    void testSendActivationEmailUsesTenantDomain() {
        Emailer emailer = new Emailer([getSecureHttpClient: { x,y -> {} as SecureHttpClient }] as TenantTokenSecureHttpClientProvider)
        emailer.emailClient = new EmailClient([post: { x, y -> "{}" }] as SecureHttpClient)
        emailer.tenantRepository = [filter: { f -> [new Tenant(guid: "abc", domain: "example.com")] }] as Repository

        assert emailer.sendActivationEmail("trevorism@gmail.com", "abc")
    }

    @Test
    void testSendActivationEmailDefaultsWhenTenantNotFound() {
        Emailer emailer = new Emailer([getSecureHttpClient: { x,y -> {} as SecureHttpClient }] as TenantTokenSecureHttpClientProvider)
        emailer.emailClient = new EmailClient([post: { x, y -> "{}" }] as SecureHttpClient)
        emailer.tenantRepository = [filter: { f -> [] }] as Repository

        assert emailer.sendActivationEmail("trevorism@gmail.com", "missing")
    }
}
