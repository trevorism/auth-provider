package com.trevorism.auth.service

import com.trevorism.auth.bean.TenantTokenSecureHttpClientProvider
import com.trevorism.auth.model.App
import com.trevorism.auth.model.Tenant
import com.trevorism.data.Repository
import org.junit.jupiter.api.Test

class DefaultRedirectUriPolicyTest {

    private static DefaultRedirectUriPolicy createPolicy(List<Tenant> tenants = [], List<App> apps = [], List<String> tenantDomains = ["memowand.com"]) {
        DefaultRedirectUriPolicy policy = new DefaultRedirectUriPolicy([getSecureHttpClient: { t, a -> null }] as TenantTokenSecureHttpClientProvider)
        policy.configuration = new HandoffConfiguration(gcpProjects: ["trevorism-project", "trevorism-auth"], tenantDomains: tenantDomains)
        policy.@tenantRepository = [list: { -> tenants }] as Repository<Tenant>
        policy.@appRepository = [list: { -> apps }] as Repository<App>
        return policy
    }

    @Test
    void testPlatformDomainAllowed() {
        DefaultRedirectUriPolicy policy = createPolicy()
        assert policy.isAllowed("https://certs.project.trevorism.com/api/auth/callback")
        assert policy.isAllowed("https://trevorism.com/api/auth/callback")
        assert policy.isAllowed("https://WWW.Trevorism.com/api/auth/callback")
    }

    @Test
    void testLookalikeDomainRejected() {
        DefaultRedirectUriPolicy policy = createPolicy()
        assert !policy.isAllowed("https://trevorism.com.evil.net/api/auth/callback")
        assert !policy.isAllowed("https://eviltrevorism.com/api/auth/callback")
    }

    @Test
    void testTenantDomainAllowed() {
        DefaultRedirectUriPolicy policy = createPolicy([new Tenant(domain: "memowand.com")])
        assert policy.isAllowed("https://memowand.com/api/auth/callback")
        assert policy.isAllowed("https://app.memowand.com/api/auth/callback")
        assert !policy.isAllowed("https://memowand.org/api/auth/callback")
    }

    @Test
    void testKnownAppspotProjectAllowed() {
        DefaultRedirectUriPolicy policy = createPolicy()
        assert policy.isAllowed("https://pr-12-dot-certs-dot-trevorism-project.uc.r.appspot.com/api/auth/callback")
        assert policy.isAllowed("https://trevorism-auth.appspot.com/api/auth/callback")
        assert policy.isAllowed("https://login-dot-trevorism-auth.uc.r.appspot.com/api/auth/callback")
    }

    @Test
    void testUnknownAppspotProjectRejected() {
        DefaultRedirectUriPolicy policy = createPolicy()
        assert !policy.isAllowed("https://evil.appspot.com/api/auth/callback")
        assert !policy.isAllowed("https://pr-1-dot-certs-dot-trevorism-evil.uc.r.appspot.com/api/auth/callback")
    }

    @Test
    void testLocalhostAllowedOverHttp() {
        DefaultRedirectUriPolicy policy = createPolicy()
        assert policy.isAllowed("http://localhost:5173/api/auth/callback")
        assert policy.isAllowed("http://127.0.0.1:8080/api/auth/callback")
        assert policy.isAllowed("https://localhost/api/auth/callback")
        assert !policy.isAllowed("http://localhost.evil.net/api/auth/callback")
    }

    @Test
    void testHttpRejectedForRemoteHosts() {
        DefaultRedirectUriPolicy policy = createPolicy()
        assert !policy.isAllowed("http://certs.project.trevorism.com/api/auth/callback")
    }

    @Test
    void testCallbackPathRequired() {
        DefaultRedirectUriPolicy policy = createPolicy()
        assert !policy.isAllowed("https://certs.project.trevorism.com/")
        assert !policy.isAllowed("https://certs.project.trevorism.com/api/auth/callback/extra")
        assert !policy.isAllowed("https://certs.project.trevorism.com/api/auth/callback?next=x")
        assert !policy.isAllowed("https://certs.project.trevorism.com/api/auth/callback#frag")
        assert !policy.isAllowed("https://user@certs.project.trevorism.com/api/auth/callback")
    }

    @Test
    void testRegisteredReplyUrlAllowedExactly() {
        App active = new App(active: true, replyUrls: ["https://partner.example.org/oauth/return"])
        App inactive = new App(active: false, replyUrls: ["https://retired.example.org/oauth/return"])
        DefaultRedirectUriPolicy policy = createPolicy([], [active, inactive])
        assert policy.isAllowed("https://partner.example.org/oauth/return")
        assert !policy.isAllowed("https://partner.example.org/oauth/return/")
        assert !policy.isAllowed("https://retired.example.org/oauth/return")
    }

    @Test
    void testGarbageRejected() {
        DefaultRedirectUriPolicy policy = createPolicy()
        assert !policy.isAllowed(null)
        assert !policy.isAllowed("")
        assert !policy.isAllowed("not a uri")
        assert !policy.isAllowed("javascript:alert(1)")
        assert !policy.isAllowed("/api/auth/callback")
    }

    @Test
    void testTenantDomainNotInConfigurationIsRejected() {
        DefaultRedirectUriPolicy policy = createPolicy([new Tenant(domain: "sample.com")])

        assert !policy.isAllowed("https://anything.sample.com/api/auth/callback")
        assert !policy.isAllowed("https://sample.com/api/auth/callback")
    }

    @Test
    void testNoConfiguredTenantDomainsMeansNoTenantIsAllowed() {
        DefaultRedirectUriPolicy policy = createPolicy([new Tenant(domain: "memowand.com")], [], [])

        assert !policy.isAllowed("https://app.memowand.com/api/auth/callback")
        assert policy.isAllowed("https://certs.project.trevorism.com/api/auth/callback")
    }

    @Test
    void testDatastoreFailureFallsBackToStaticRules() {
        DefaultRedirectUriPolicy policy = createPolicy()
        policy.@tenantRepository = [list: { -> throw new RuntimeException("down") }] as Repository<Tenant>
        assert policy.isAllowed("https://certs.project.trevorism.com/api/auth/callback")
        assert !policy.isAllowed("https://memowand.com/api/auth/callback")
    }

    @Test
    void testDatastoreFailureIsNotRetriedOnEveryCall() {
        int attempts = 0
        DefaultRedirectUriPolicy policy = createPolicy()
        policy.@tenantRepository = [list: { -> attempts++; throw new RuntimeException("down") }] as Repository<Tenant>

        5.times { policy.isAllowed("https://memowand.com/api/auth/callback") }

        assert attempts == 1
    }

    @Test
    void testSuccessfulLoadIsCached() {
        int attempts = 0
        DefaultRedirectUriPolicy policy = createPolicy()
        policy.@tenantRepository = [list: { -> attempts++; [new Tenant(domain: "memowand.com")] }] as Repository<Tenant>

        5.times { assert policy.isAllowed("https://memowand.com/api/auth/callback") }

        assert attempts == 1
    }
}
