package com.trevorism.auth.service

import com.trevorism.auth.bean.SecureHttpClientProvider
import com.trevorism.data.FastDatastoreRepository
import com.trevorism.data.Repository
import com.trevorism.data.model.filtering.FilterBuilder
import com.trevorism.data.model.filtering.SimpleFilter
import com.trevorism.auth.model.Identity
import com.trevorism.auth.model.SaltedPassword
import com.trevorism.auth.model.User
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.time.Instant
import java.time.temporal.ChronoUnit

@jakarta.inject.Singleton
class DefaultUserCredentialService implements UserCredentialService {

    private static final Logger log = LoggerFactory.getLogger(DefaultUserCredentialService)

    private Repository<User> repository
    private Emailer emailer

    DefaultUserCredentialService(SecureHttpClientProvider provider){
        repository = new FastDatastoreRepository<>(User, provider.getSecureHttpClient())
        emailer = new Emailer(provider.getSecureHttpClient())
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
    User registerUser(User user) {
        if (!validateRegistration(user)) {
            throw new RuntimeException("Unable to register user without credentials")
        }

        user.active = false
        user.dateCreated = new Date()
        user.username = user.username.toLowerCase()

        User secureUser = setPasswordAndSalt(user)
        User createdUser = repository.create(secureUser)
        emailer.sendRegistrationEmail(user.username, user.email)
        return cleanUser(createdUser)
    }

    @Override
    boolean validateCredentials(String username, String password) {
        if (!username || !password) {
            return false
        }

        User user = getUserCredential(username)

        if (!user || !user.username || !user.password || !user.salt || !user.active || HashUtils.isExpired(user.dateExpired)) {
            return false
        }

        return validatePasswordsMatch(user, password)
    }

    @Override
    Identity getIdentity(String identifier) {
        getUserCredential(identifier)
    }

    @Override
    boolean validateRegistration(User user) {
        if (!user || !user.username || !user.password || !user.email) {
            log.warn("Registration missing a required field")
            return false
        }
        if (user.username.length() < 3 || user.password.length() < 6) {
            log.warn("Registration username/password length not acceptable")
            return false
        }
        if (!user.email.contains("@")) {
            log.warn("Email is not formatted correctly")
            return false
        }
        if (getUserCredential(user.username)) {
            log.warn("Registration detected duplicate username")
            return false
        }
        return true
    }

    @Override
    boolean activateUser(User user, boolean admin) {
        User toUpdate = getIdentity(user.identifer) as User
        toUpdate.active = true
        toUpdate.admin = admin
        toUpdate.dateExpired = Date.from(Instant.now().plus(365, ChronoUnit.DAYS))
        def result = repository.update(toUpdate.id, toUpdate)
        if (result) {
            emailer.sendActivationEmail(user.email)
            return true
        }
        return false
    }

    @Override
    boolean deactivateUser(User user) {
        User toUpdate = getIdentity(user.identifer) as User
        toUpdate.active = false
        return repository.update(toUpdate.id, toUpdate)
    }

    @Override
    boolean changePassword(Identity identity, String currentPassword, String newPassword) {
        User user = getUserCredential(identity.getIdentifer())
        if (!validatePasswordsMatch(user, currentPassword)) {
            return false
        }
        user.password = newPassword
        user = setPasswordAndSalt(user)
        user.dateExpired = Date.from(Instant.now().plus(365, ChronoUnit.DAYS))

        repository.update(user.id, user)
    }

    @Override
    void forgotPassword(Identity identity) {
        User user = getUserCredential(identity.getIdentifer())
        if (!user) {
            throw new RuntimeException("Unable to locate user: ${identity.identifer}")
        }
        String newPassword = HashUtils.generateRawSecret()
        user.password = newPassword
        user = setPasswordAndSalt(user)
        user.dateExpired = Date.from(Instant.now().plus(1, ChronoUnit.DAYS))
        repository.update(user.id, user)

        emailer.sendForgotPasswordEmail(user.email, newPassword)
    }

    private User getUserCredential(String username) {
        try{
            return repository.filter(new FilterBuilder().addFilter(new SimpleFilter("username", "=", username.toLowerCase())).build())[0]
        }catch(Exception e){
            log.error("Unable to retrieve user credentials from database for user: ${username} with message: ${e.message}")
            return null
        }
    }

    private static User cleanUser(User user) {
        user?.password = null
        user?.salt = null
        return user
    }

    private static User setPasswordAndSalt(User user) {
        SaltedPassword sp = HashUtils.createPasswordAndSalt(user.password)
        user.salt = sp.salt
        user.password = sp.password
        return user
    }

    private static boolean validatePasswordsMatch(User user, String password) {
        SaltedPassword sp = new SaltedPassword(user.salt, user.password)
        return HashUtils.validatePasswordsMatch(sp, password)
    }
}
