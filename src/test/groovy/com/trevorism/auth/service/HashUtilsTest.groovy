package com.trevorism.auth.service


import org.junit.jupiter.api.Test

import java.time.Instant

class HashUtilsTest {

    @Test
    void testGenerateAndValidatePassword() {
        com.trevorism.auth.model.SaltedPassword saltedPassword = HashUtils.createPasswordAndSalt("test")
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
        Date after = Date.from(Instant.now().plusSeconds(10))
        Date before = Date.from(Instant.now().plusSeconds(-10))

        assert HashUtils.isExpired(before)
        assert !HashUtils.isExpired(after)
    }
}
