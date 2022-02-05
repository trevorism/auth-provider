package com.trevorism.gcloud.webapi.service

import com.trevorism.data.Repository
import com.trevorism.data.exception.IdMissingException
import com.trevorism.data.model.filtering.ComplexFilter
import com.trevorism.data.model.paging.PageRequest
import com.trevorism.data.model.sorting.ComplexSort
import com.trevorism.gcloud.webapi.model.App
import com.trevorism.gcloud.webapi.model.SaltedPassword
import org.junit.Test

import java.time.Instant
import java.time.ZoneId

class DefaultAppRegistrationServiceTest {

    @Test
    void testListRegisteredApps() {
        DefaultAppRegistrationService service = new DefaultAppRegistrationService()
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
        DefaultAppRegistrationService service = new DefaultAppRegistrationService()
        service.repository = new TestAppRepository()
        assert service.getRegisteredApp("5721612393381888")
        assert !service.getRegisteredApp("4")
    }

    @Test
    void testRemoveRegisteredApp() {
        DefaultAppRegistrationService service = new DefaultAppRegistrationService()
        service.repository = new TestAppRepository()
        assert service.removeRegisteredApp("5721612393381888")
        assert !service.removeRegisteredApp("4")
    }

    @Test
    void testRegisterApp() {
        DefaultAppRegistrationService service = new DefaultAppRegistrationService()
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
        DefaultAppRegistrationService service = new DefaultAppRegistrationService()
        service.repository = new TestAppRepository()
        String secret = service.generateClientSecret(new App(id: "5721612393381888", clientId: "fc64fb13-216d-4592-8bc9-79f087e14f9a"))
        assert service.validateCredentials("fc64fb13-216d-4592-8bc9-79f087e14f9a", secret)
    }

    @Test
    void testValidateApp() {
        DefaultAppRegistrationService service = new DefaultAppRegistrationService()
        service.repository = new TestAppRepository()
        assert service.validateApp(new App(id: "5721612393381888", clientId: "fc64fb13-216d-4592-8bc9-79f087e14f9a"))
    }

    @Test(expected = Exception)
    void testValidateAppWithBadId() {
        DefaultAppRegistrationService service = new DefaultAppRegistrationService()
        service.repository = new TestAppRepository()
        assert service.validateApp(new App(id: "2", clientId: "fc64fb13-216d-4592-8bc9-79f087e14f9a"))
    }

    @Test(expected = Exception)
    void testValidateAppWithBadClientId() {
        DefaultAppRegistrationService service = new DefaultAppRegistrationService()
        service.repository = new TestAppRepository()
        assert service.validateApp(new App(id: "5721612393381888", clientId: "7"))
    }

    @Test
    void testGetIdentity() {
        DefaultAppRegistrationService service = new DefaultAppRegistrationService()
        service.repository = new TestAppRepository()
        assert service.getIdentity("fc64fb13-216d-4592-8bc9-79f087e14f9a")
        assert !service.getIdentity("123")
    }

    class TestAppRepository implements Repository<App>{

        SaltedPassword sp = new SaltedPassword()

        @Override
        List<App> list() {
            return list(null)
        }

        @Override
        List<App> list(String s) {
            return [new App(id:1, appName: "test", clientId: "fc64fb13-216d-4592-8bc9-79f087e14f9a", active: true,
                    dateCreated: new Date(),
                    dateExpired: Instant.now().atZone(ZoneId.systemDefault()).toLocalDateTime().plusYears(1).toDate(),
                    salt: sp.salt, clientSecret: sp.password)]
        }

        @Override
        App get(String s) {
            return get(s, null)
        }

        @Override
        App get(String s, String s1) {
            if(s == "5721612393381888"){
                return new App(id: "5721612393381888", clientId: "fc64fb13-216d-4592-8bc9-79f087e14f9a")
            }
            return null
        }

        @Override
        App create(App app) {
            create(app, null)
        }

        @Override
        App create(App app, String s) {
            return app
        }

        @Override
        App update(String s, App app) {
            return update(s, app, null)
        }

        @Override
        App update(String s, App app, String s1) {
            sp = new SaltedPassword(app.salt, app.clientSecret)
            return app
        }

        @Override
        App delete(String s) {
            return delete(s, null)
        }

        @Override
        App delete(String s, String s1) {
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
