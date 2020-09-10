package com.trevorism.gcloud.webapi.service

import com.google.common.base.Charsets
import com.trevorism.gcloud.webapi.model.SaltedPassword
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.io.Encoders

import java.security.MessageDigest
import java.security.SecureRandom

class HashUtils {

    private static final String HASHING_ALGORITHM = "SHA-512"

    private static byte [] createSalt() {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG")
        byte[] salt = new byte[16]
        sr.nextBytes(salt)
        return salt
    }

    static SaltedPassword createPasswordAndSalt(String rawPassword) {
        MessageDigest md = MessageDigest.getInstance(HASHING_ALGORITHM)
        byte[] saltBytes = createSalt()
        md.update(saltBytes)
        byte[] hashed = md.digest(rawPassword.getBytes(Charsets.UTF_8))
        new SaltedPassword(Encoders.BASE64.encode(saltBytes), Encoders.BASE64.encode(hashed))
    }

    static String generateRawSecret() {
        String str = UUID.randomUUID().toString()
        str = str.replaceAll("-", "")
        Random random = new Random()
        int lowerbound = random.nextInt(5)
        int upperBound = random.nextInt(5) + 15
        return str[lowerbound..upperBound]
    }

    static boolean validatePasswordsMatch(SaltedPassword saltedPassword, String rawPassword) {
        MessageDigest md = MessageDigest.getInstance(HASHING_ALGORITHM)
        md.update(Decoders.BASE64.decode(saltedPassword.salt))
        byte[] hashed = md.digest(rawPassword.getBytes(Charsets.UTF_8))
        String hashedPasswordString = Encoders.BASE64.encode(hashed)
        return hashedPasswordString == saltedPassword.password
    }

    static boolean isExpired(Date dateExpired){
        dateExpired.before(new Date())
    }
}
