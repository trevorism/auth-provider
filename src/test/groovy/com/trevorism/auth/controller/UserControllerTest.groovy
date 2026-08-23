package com.trevorism.auth.controller

import com.trevorism.auth.model.ChangePasswordRequest
import com.trevorism.auth.service.TenantAwareUserService
import org.junit.jupiter.api.Test

class UserControllerTest {

    @Test
    void testChangePasswordReportsTheServiceRefusal() {
        UserController controller = controllerThatChangesPasswords { ChangePasswordRequest request -> false }

        assert !controller.changePassword(new ChangePasswordRequest(username: "alice",
                currentPassword: "wrong", desiredPassword: "secret2", tenantGuid: "guid-1"))
    }

    @Test
    void testChangePasswordReportsSuccess() {
        List<ChangePasswordRequest> requests = []
        UserController controller = controllerThatChangesPasswords { ChangePasswordRequest request ->
            requests << request
            return true
        }

        assert controller.changePassword(new ChangePasswordRequest(username: "alice",
                currentPassword: "secret1", desiredPassword: "secret2", tenantGuid: "guid-1"))
        assert requests[0].tenantGuid == "guid-1"
    }

    @Test
    void testChangePasswordReportsAFailureFromTheDatastore() {
        UserController controller = controllerThatChangesPasswords { ChangePasswordRequest request ->
            throw new RuntimeException("datastore is unreachable")
        }

        assert !controller.changePassword(new ChangePasswordRequest(username: "alice"))
    }

    private static UserController controllerThatChangesPasswords(Closure<Boolean> behavior) {
        UserController controller = new UserController()
        controller.tenantAwareUserService = new TenantAwareUserService() {
            @Override
            boolean changePassword(ChangePasswordRequest changePasswordRequest) {
                return behavior.call(changePasswordRequest)
            }
        }
        return controller
    }
}
