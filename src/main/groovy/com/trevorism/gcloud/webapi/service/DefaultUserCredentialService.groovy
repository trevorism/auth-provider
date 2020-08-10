package com.trevorism.gcloud.webapi.service

import com.google.common.base.Charsets
import com.trevorism.data.PingingDatastoreRepository
import com.trevorism.data.Repository
import com.trevorism.gcloud.webapi.model.User
import io.jsonwebtoken.io.Decoders
import io.jsonwebtoken.io.Encoders

import java.security.MessageDigest
import java.security.SecureRandom

class DefaultUserCredentialService implements UserCredentialService{

    private static final String HASHING_ALGORITHM = "SHA-512"
    private Repository<User> repository = new PingingDatastoreRepository<>(User)

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
        repository.list().collect{
            cleanUser(it)
        }
    }

    @Override
    User registerUser(User user) {
        if(!validateRegistration(user)) {
            throw new RuntimeException("Unable to register user without credentials")
        }

        User secureUser = setPasswordAndSalt(user)
        User createdUser = repository.create(secureUser)
        return cleanUser(createdUser)
    }

    @Override
    boolean validateCredentials(String username, String password) {
        User user = getUserCredential(username)

        if(!user || !user.username || !user.password || !user.salt){
            return false
        }

        return validatePasswordsMatch(user, password)
    }

    @Override
    boolean validateRegistration(User user) {
        if(!user || !user.username || !user.password || !user.email){
            return false
        }
        if(getUserCredential(user.username)){
            return false
        }
        if(user.password.length() < 6)
            return false

        return true
    }

    private User getUserCredential(String username) {
        return repository.list().find{
            it.username == username
        }
    }

    private byte [] createSalt() {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG")
        byte[] salt = new byte[16]
        sr.nextBytes(salt)
        return salt
    }

    private User cleanUser(User user) {
        user.password = null
        user.salt = null
        return user
    }

    private User setPasswordAndSalt(User user) {
        MessageDigest md = MessageDigest.getInstance(HASHING_ALGORITHM)
        byte[] saltBytes = createSalt()
        md.update(saltBytes)
        byte[] hashed = md.digest(user.password.getBytes(Charsets.UTF_8))

        user.salt = Encoders.BASE64.encode(saltBytes)
        user.password = Encoders.BASE64.encode(hashed)

        return user
    }

    private static boolean validatePasswordsMatch(User user, String password) {
        MessageDigest md = MessageDigest.getInstance(HASHING_ALGORITHM)
        md.update(Decoders.BASE64.decode(user.salt))
        byte[] hashed = md.digest(password.getBytes(Charsets.UTF_8))
        String hashedPasswordString = Encoders.BASE64.encode(hashed)
        return hashedPasswordString == user.password
    }
}
