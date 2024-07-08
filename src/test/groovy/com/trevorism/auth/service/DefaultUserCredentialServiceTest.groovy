package com.trevorism.auth.service

import com.trevorism.auth.model.*
import com.trevorism.data.Repository
import com.trevorism.data.model.filtering.ComplexFilter
import com.trevorism.data.model.filtering.SimpleFilter
import com.trevorism.data.model.paging.PageRequest
import com.trevorism.data.model.sorting.ComplexSort
import com.trevorism.data.model.sorting.Sort
import com.trevorism.https.SecureHttpClient
import com.trevorism.secure.Roles
import io.micronaut.security.authentication.Authentication
import org.junit.jupiter.api.Test

import java.time.Instant

class DefaultUserCredentialServiceTest {

    @Test
    void testGetUser() {
        UserService service = new DefaultUserCredentialService({} as SecureHttpClient)
        service.repository = new TestUserRepository()
        assert service.getUser("5154038974775296")
        assert !service.getUser("6")
    }

    @Test
    void testDeleteUser() {
        UserService service = new DefaultUserCredentialService({} as SecureHttpClient)
        service.repository = new TestUserRepository()
        assert service.deleteUser("5154038974775296")
        assert !service.deleteUser("6")
    }

    @Test
    void testListUsers() {
        UserService service = new DefaultUserCredentialService({} as SecureHttpClient)
        service.repository = new TestUserRepository()
        assert service.listUsers()
    }

    @Test
    void testGetIdentity() {
        UserService service = new DefaultUserCredentialService({} as SecureHttpClient)
        service.repository = new TestUserRepository()
        assert service.getIdentity("test")
        assert !service.getIdentity("notThere")
    }

    class TestUserRepository implements Repository<User> {

        TestUserRepository(){

        }

        @Override
        List<User> all() {
            list()
        }

        @Override
        List<User> list() {
            [new User(username: "test", salt: "5CeJI8KtC6TyTEsHAQCj4g==", email: "test@trevorism.com",
                    password: "tqrJyIlVuOhW79QFzBPgZcOjbR18osSOSUh9pYyzEl+6NqBnqwU8Mal70kKP4TH+qgcwedC9xNkb0gO8HjIYQA==",
                    dateExpired: Date.from(Instant.now().plusSeconds(100)),
                    active: true
            )]
        }

        @Override
        User get(String s) {
            if (s == "5154038974775296")
                return new User()
            return null
        }

        @Override
        User create(User user) {
            return user
        }

        @Override
        User update(String s, User user) {
            return user
        }

        @Override
        User delete(String s) {
            if (s == "5154038974775296")
                return new User()
            return null
        }

        @Override
        void ping() {

        }

        @Override
        List<User> filter(ComplexFilter complexFilter) {
            if (complexFilter?.simpleFilters?.get(0).value == "test")
                return list()
            return []
        }

        @Override
        List<User> filter(SimpleFilter simpleFilter) {
            if(simpleFilter.value == "test")
                return list()
            return []
        }

        @Override
        List<User> page(PageRequest pageRequest) {
            return list()
        }

        @Override
        List<User> sort(ComplexSort complexSort) {
            return list()
        }

        @Override
        List<User> sort(Sort sort) {
            return list()
        }
    }
}
