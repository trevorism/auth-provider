package com.trevorism.gcloud.webapi.service

import com.trevorism.gcloud.webapi.model.UserRole

interface RoleService {

    UserRole create(UserRole userRole)
    UserRole update(String id, UserRole userRole)
    List<UserRole> list()
    UserRole get(String id)
    UserRole delete(String id)

    UserRole findByUserId(String userId)
}