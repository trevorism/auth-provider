package com.trevorism.gcloud.webapi.service

import com.trevorism.data.PingingDatastoreRepository
import com.trevorism.data.Repository
import com.trevorism.gcloud.webapi.model.UserRole

class DefaultUserRoleService implements RoleService{

    private Repository<UserRole> repository = new PingingDatastoreRepository<>(UserRole)

    @Override
    UserRole create(UserRole userRole) {
        return repository.create(userRole)
    }

    @Override
    UserRole update(String id, UserRole userRole) {
        return repository.update(id, userRole)
    }

    @Override
    List<UserRole> list() {
        return repository.list()
    }

    @Override
    UserRole get(String id) {
        return repository.get(id)
    }

    @Override
    UserRole delete(String id) {
        return repository.delete(id)
    }

    @Override
    UserRole findByUserId(String userId) {
        list().find{
            it.userId == userId
        }
    }
}
