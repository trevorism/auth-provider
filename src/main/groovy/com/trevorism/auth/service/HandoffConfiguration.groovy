package com.trevorism.auth.service

import io.micronaut.context.annotation.ConfigurationProperties

@ConfigurationProperties("trevorism.handoff")
class HandoffConfiguration {
    List<String> gcpProjects = []
    int codeLifetimeSeconds = 60
}
