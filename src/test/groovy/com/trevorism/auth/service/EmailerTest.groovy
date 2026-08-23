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
        List<String> posted = []
        Emailer emailer = emailerRecordingInto(posted)

        assert emailer.sendForgotPasswordEmail("trevorism@gmail.com", "username", "12345678", "trevorism.com", null)
        assert posted[0].contains("https://trevorism.com/change")
        assert !posted[0].contains("https://trevorism.com/change/")
    }

    @Test
    void testSendForgotPasswordEmailPointsATenantUserAtTheirOwnTenant() {
        List<String> posted = []
        Emailer emailer = emailerRecordingInto(posted)

        assert emailer.sendForgotPasswordEmail("trevorism@gmail.com", "username", "12345678", "trevorism.com", "guid-1")
        assert posted[0].contains("https://trevorism.com/change/guid-1")
    }

    private static Emailer emailerRecordingInto(List<String> posted) {
        Emailer emailer = new Emailer([getSecureHttpClient: { x,y -> {} as SecureHttpClient }] as TenantTokenSecureHttpClientProvider)
        emailer.emailClient = new EmailClient([post: { x, y ->
            posted << y as String
            return "{}"
        }] as SecureHttpClient)
        return emailer
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

    @Test
    void testSendActivationEmailWithoutTenantGuid() {
        Emailer emailer = new Emailer([getSecureHttpClient: { x,y -> {} as SecureHttpClient }] as TenantTokenSecureHttpClientProvider)
        emailer.emailClient = new EmailClient([post: { x, y -> "{}" }] as SecureHttpClient)
        emailer.tenantRepository = [filter: { f -> throw new IllegalStateException("should not query for a null tenant") }] as Repository

        assert emailer.sendActivationEmail("trevorism@gmail.com", null)
    }
}
