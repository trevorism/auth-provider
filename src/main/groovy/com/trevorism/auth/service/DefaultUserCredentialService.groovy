package com.trevorism.auth.service


import com.trevorism.auth.model.*
import com.trevorism.data.FastDatastoreRepository
import com.trevorism.data.Repository
import com.trevorism.data.model.filtering.FilterBuilder
import com.trevorism.data.model.filtering.SimpleFilter
import com.trevorism.https.SecureHttpClient
import org.slf4j.Logger
import org.slf4j.LoggerFactory

@jakarta.inject.Singleton
class DefaultUserCredentialService implements UserService {

    private static final Logger log = LoggerFactory.getLogger(DefaultUserCredentialService)
    private Repository<User> repository

    DefaultUserCredentialService(SecureHttpClient httpClient) {
        repository = new FastDatastoreRepository<>(User, httpClient)
    }

    @Override
    User getUser(String id) {
        User user = repository.get(id)
        return cleanUser(user)
    }

    @Override
    User deleteUser(String id) {
        User user = repository.delete(id)
        return cleanUser(user)
    }

    @Override
    List<User> listUsers() {
        repository.list().collect {
            cleanUser(it)
        }
    }

    @Override
    Identity getIdentity(String identifier) {
        getUserByUsername(identifier)
    }

    private User getUserByUsername(String username) {
        try {
            return repository.filter(new FilterBuilder().addFilter(new SimpleFilter("username", "=", username.toLowerCase())).build())[0]
        } catch (Exception e) {
            log.error("Unable to retrieve user credentials from database for user: ${username} with message: ${e.message}")
            return null
        }
    }

    private static User cleanUser(User user) {
        user?.password = null
        user?.salt = null
        return user
    }

}
