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
        emailer.tenantRepository = [filter: { f -> [new Tenant(guid: "guid-1", domain: "acme.com")] }] as Repository

        assert emailer.sendForgotPasswordEmail("trevorism@gmail.com", "username", "12345678", "trevorism.com", "guid-1")
        assert posted[0].contains("https://trevorism.com/change/guid-1")
    }

    @Test
    void testSendForgotPasswordEmailNamesTheTenantRatherThanTrevorism() {
        List<String> posted = []
        Emailer emailer = emailerRecordingInto(posted)
        emailer.tenantRepository = [filter: { f -> [new Tenant(guid: "guid-1", domain: "acme.com")] }] as Repository

        assert emailer.sendForgotPasswordEmail("trevorism@gmail.com", "username", "12345678", "trevorism.com", "guid-1")
        assert posted[0].contains("acme.com: Reset Password")
        assert posted[0].contains("your username account on acme.com")
        assert !posted[0].contains("account on trevorism.com")
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
        List<String> posted = []
        Emailer emailer = emailerRecordingInto(posted)
        emailer.tenantRepository = [filter: { f -> [new Tenant(guid: "abc", domain: "example.com")] }] as Repository

        assert emailer.sendActivationEmail("trevorism@gmail.com", "abc")
        assert posted[0].contains("example.com: Activation")
        assert posted[0].contains("activated on example.com")
    }

    @Test
    void testSendActivationEmailPointsATenantUserAtTheirTenantLogin() {
        List<String> posted = []
        Emailer emailer = emailerRecordingInto(posted)
        emailer.tenantRepository = [filter: { f -> [new Tenant(guid: "abc", domain: "example.com")] }] as Repository

        assert emailer.sendActivationEmail("trevorism@gmail.com", "abc")
        assert posted[0].contains("https://login.auth.trevorism.com/abc")
        assert !posted[0].contains("https://example.com")
    }

    @Test
    void testSendActivationEmailDefaultsWhenTenantNotFound() {
        List<String> posted = []
        Emailer emailer = emailerRecordingInto(posted)
        emailer.tenantRepository = [filter: { f -> [] }] as Repository

        assert emailer.sendActivationEmail("trevorism@gmail.com", "missing")
        assert posted[0].contains("https://login.auth.trevorism.com/missing")
    }

    @Test
    void testSendActivationEmailWithoutTenantGuid() {
        List<String> posted = []
        Emailer emailer = emailerRecordingInto(posted)
        emailer.tenantRepository = [filter: { f -> throw new IllegalStateException("should not query for a null tenant") }] as Repository

        assert emailer.sendActivationEmail("trevorism@gmail.com", null)
        assert posted[0].contains("Trevorism: Activation")
        assert posted[0].contains("Login to https://login.auth.trevorism.com")
        assert !posted[0].contains("login.auth.trevorism.com/null")
    }
}
