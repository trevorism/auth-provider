package com.trevorism.gcloud.webapi.service

import com.trevorism.gcloud.webapi.model.SaltedPassword
import org.junit.Test

import java.time.Instant

class HashUtilsTest {

    @Test
    void testGenerateAndValidatePassword() {
        SaltedPassword saltedPassword = HashUtils.createPasswordAndSalt("test")
        assert saltedPassword
        assert saltedPassword.password
        assert saltedPassword.salt

        assert HashUtils.validatePasswordsMatch(saltedPassword, "test")
        assert !HashUtils.validatePasswordsMatch(saltedPassword, "test1")
    }

    @Test
    void testGenerateRawSecret() {
        String secret = HashUtils.generateRawSecret()
        assert secret
        assert secret.length() >= 10
    }

    @Test
    void testIsExpired() {
        Date after = Instant.now().plusSeconds(10).toDate()
        Date before = Instant.now().plusSeconds(-10).toDate()

        assert HashUtils.isExpired(before)
        assert !HashUtils.isExpired(after)
    }
}
