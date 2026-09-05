package com.trevorism.auth.service

import io.micronaut.context.annotation.ConfigurationProperties

@ConfigurationProperties("trevorism.handoff")
class HandoffConfiguration {
    List<String> gcpProjects = []
    List<String> tenantDomains = []
    int codeLifetimeSeconds = 60
}
