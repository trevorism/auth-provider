package com.trevorism.auth.service

import com.trevorism.auth.bean.SecureHttpClientProvider
import com.trevorism.data.Repository
import com.trevorism.data.model.filtering.ComplexFilter
import com.trevorism.data.model.paging.PageRequest
import com.trevorism.data.model.sorting.ComplexSort
import com.trevorism.auth.model.App
import com.trevorism.auth.model.SaltedPassword
import org.junit.jupiter.api.Test

import java.time.Instant
import java.time.temporal.ChronoUnit

import static org.junit.jupiter.api.Assertions.assertThrows

class DefaultAppRegistrationServiceTest {

    @Test
    void testListRegisteredApps() {
        DefaultAppRegistrationService service = new DefaultAppRegistrationService({} as SecureHttpClientProvider)
        service.repository = new TestAppRepository()
        def list = service.listRegisteredApps()
        assert list
        assert list[0]
        assert list[0].id
        assert list[0].clientId
        assert list[0].identifer
        assert list[0].active
        assert list[0].dateCreated
        assert list[0].dateExpired
    }

    @Test
    void testGetRegisteredApp() {
        DefaultAppRegistrationService service = new DefaultAppRegistrationService({} as SecureHttpClientProvider)
        service.repository = new TestAppRepository()
        assert service.getRegisteredApp("5721612393381888")
        assert !service.getRegisteredApp("4")
    }

    @Test
    void testRemoveRegisteredApp() {
        DefaultAppRegistrationService service = new DefaultAppRegistrationService({} as SecureHttpClientProvider)
        service.repository = new TestAppRepository()
        assert service.removeRegisteredApp("5721612393381888")
        assert !service.removeRegisteredApp("4")
    }

    @Test
    void testRegisterApp() {
        DefaultAppRegistrationService service = new DefaultAppRegistrationService({} as SecureHttpClientProvider)
        service.repository = new TestAppRepository()
        App app = new App(appName: "firstAppTest")

        App registered = service.registerApp(app)

        assert registered.active
        assert registered.dateCreated
        assert registered.dateExpired
        assert registered.clientId
    }

    @Test
    void testGenerateClientSecretAndValidateIt() {
        DefaultAppRegistrationService service = new DefaultAppRegistrationService({} as SecureHttpClientProvider)
        service.repository = new TestAppRepository()
        String secret = service.generateClientSecret(new App(id: "5721612393381888", clientId: "fc64fb13-216d-4592-8bc9-79f087e14f9a"))
        assert service.validateCredentials("fc64fb13-216d-4592-8bc9-79f087e14f9a", secret)
    }

    @Test
    void testValidateApp() {
        DefaultAppRegistrationService service = new DefaultAppRegistrationService({} as SecureHttpClientProvider)
        service.repository = new TestAppRepository()
        assert service.validateApp(new App(id: "5721612393381888", clientId: "fc64fb13-216d-4592-8bc9-79f087e14f9a"))
    }

    @Test
    void testValidateAppWithBadId() {
        DefaultAppRegistrationService service = new DefaultAppRegistrationService({} as SecureHttpClientProvider)
        service.repository = new TestAppRepository()
        assertThrows(RuntimeException, () -> service.validateApp(new App(id: "2", clientId: "fc64fb13-216d-4592-8bc9-79f087e14f9a")))
    }

    @Test
    void testValidateAppWithBadClientId() {
        DefaultAppRegistrationService service = new DefaultAppRegistrationService({} as SecureHttpClientProvider)
        service.repository = new TestAppRepository()
        assertThrows(RuntimeException, () -> service.validateApp(new App(id: "5721612393381888", clientId: "7")))
    }

    @Test
    void testGetIdentity() {
        DefaultAppRegistrationService service = new DefaultAppRegistrationService({} as SecureHttpClientProvider)
        service.repository = new TestAppRepository()
        assert service.getIdentity("fc64fb13-216d-4592-8bc9-79f087e14f9a")
        assert !service.getIdentity("123")
    }

    class TestAppRepository implements Repository<App>{

        SaltedPassword sp = new SaltedPassword()

        @Override
        List<App> all() {
            return list()
        }

        @Override
        List<App> list() {
            return [new App(id:1, appName: "test", clientId: "fc64fb13-216d-4592-8bc9-79f087e14f9a", active: true,
                    dateCreated: new Date(),
                    dateExpired: Date.from(Instant.now().plus(365, ChronoUnit.DAYS)),
                    salt: sp.salt, clientSecret: sp.password)]
        }


        @Override
        App get(String s) {
            if(s == "5721612393381888"){
                return new App(id: "5721612393381888", clientId: "fc64fb13-216d-4592-8bc9-79f087e14f9a")
            }
            return null
        }

        @Override
        App create(App app) {
            return app
        }

        @Override
        App update(String s, App app) {
            sp = new SaltedPassword(app.salt, app.clientSecret)
            return app
        }

        @Override
        App delete(String s) {
            if(s == "5721612393381888"){
                return new App(id: "5721612393381888", clientId: "fc64fb13-216d-4592-8bc9-79f087e14f9a")
            }
            return null
        }

        @Override
        void ping() {

        }

        @Override
        List<App> filter(ComplexFilter complexFilter) {
            if(complexFilter?.simpleFilters?.get(0).value == "fc64fb13-216d-4592-8bc9-79f087e14f9a")
                return list()
            return []
        }

        @Override
        List<App> page(PageRequest pageRequest) {
            return list()
        }

        @Override
        List<App> sort(ComplexSort complexSort) {
            return list()
        }
    }
}
