package com.trevorism.auth.service

import com.trevorism.auth.bean.TenantTokenSecureHttpClientProvider
import com.trevorism.auth.model.App
import com.trevorism.auth.model.Tenant
import com.trevorism.data.FastDatastoreRepository
import com.trevorism.data.Repository
import com.trevorism.https.SecureHttpClient
import jakarta.inject.Inject
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.time.Duration
import java.time.Instant
import java.util.regex.Matcher
import java.util.regex.Pattern

@jakarta.inject.Singleton
class DefaultRedirectUriPolicy implements RedirectUriPolicy {

    private static final Logger log = LoggerFactory.getLogger(DefaultRedirectUriPolicy)

    static final String CALLBACK_PATH = "/api/auth/callback"
    static final String PLATFORM_DOMAIN = "trevorism.com"
    static final List<String> LOCAL_HOSTS = ["localhost", "127.0.0.1"]
    static final Pattern APPSPOT_HOST = Pattern.compile('^(?:[a-z0-9-]+-dot-)*(?<project>[a-z0-9-]+)(?:[.][a-z0-9]+[.]r)?[.]appspot[.]com$')
    private static final Duration CACHE_DURATION = Duration.ofMinutes(5)
    private static final Duration FAILURE_RETRY_DURATION = Duration.ofSeconds(30)

    @Inject
    HandoffConfiguration configuration

    private Repository<Tenant> tenantRepository
    private Repository<App> appRepository
    private List<String> cachedTenantDomains = []
    private List<String> cachedReplyUrls = []
    private Instant nextRefreshAt = Instant.EPOCH

    DefaultRedirectUriPolicy(TenantTokenSecureHttpClientProvider tokenSecureHttpClientProvider) {
        SecureHttpClient secureHttpClient = tokenSecureHttpClientProvider.getSecureHttpClient(null, null)
        tenantRepository = new FastDatastoreRepository<>(Tenant, secureHttpClient)
        appRepository = new FastDatastoreRepository<>(App, secureHttpClient)
    }

    @Override
    boolean isAllowed(String redirectUri) {
        URI uri = parse(redirectUri)
        if (!uri) {
            return false
        }
        String host = uri.host?.toLowerCase()
        String scheme = uri.scheme?.toLowerCase()
        if (!host || !scheme || uri.rawPath != CALLBACK_PATH || uri.rawQuery != null || uri.rawFragment != null || uri.rawUserInfo != null) {
            return isRegisteredReplyUrl(redirectUri)
        }
        if (LOCAL_HOSTS.contains(host)) {
            return scheme in ["http", "https"]
        }
        if (scheme != "https") {
            return isRegisteredReplyUrl(redirectUri)
        }
        return isUnderDomain(host, PLATFORM_DOMAIN) ||
                isTenantDomain(host) ||
                isKnownAppspotProject(host) ||
                isRegisteredReplyUrl(redirectUri)
    }

    private static URI parse(String redirectUri) {
        if (!redirectUri) {
            return null
        }
        try {
            return new URI(redirectUri)
        } catch (URISyntaxException ignored) {
            return null
        }
    }

    static boolean isUnderDomain(String host, String domain) {
        String normalizedDomain = domain?.toLowerCase()?.trim()
        if (!normalizedDomain) {
            return false
        }
        return host == normalizedDomain || host.endsWith(".${normalizedDomain}")
    }

    private boolean isTenantDomain(String host) {
        refreshCacheIfStale()
        return cachedTenantDomains.any { isUnderDomain(host, it) }
    }

    private boolean isKnownAppspotProject(String host) {
        Matcher matcher = APPSPOT_HOST.matcher(host)
        if (!matcher.matches()) {
            return false
        }
        return configuration.gcpProjects.contains(matcher.group("project"))
    }

    private boolean isRegisteredReplyUrl(String redirectUri) {
        refreshCacheIfStale()
        return cachedReplyUrls.contains(redirectUri)
    }

    private synchronized void refreshCacheIfStale() {
        if (Instant.now().isBefore(nextRefreshAt)) {
            return
        }
        try {
            cachedTenantDomains = tenantRepository.list().collect { it.domain?.toLowerCase() }.findAll { it }
            cachedReplyUrls = appRepository.list().findAll { it.active }.collectMany { it.replyUrls ?: [] }
            nextRefreshAt = Instant.now().plus(CACHE_DURATION)
        } catch (Exception e) {
            nextRefreshAt = Instant.now().plus(FAILURE_RETRY_DURATION)
            log.warn("Unable to load tenants and apps for redirect allowlist, retrying in ${FAILURE_RETRY_DURATION.seconds}s: ${e.message}")
        }
    }
}
