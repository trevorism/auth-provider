package com.trevorism.gcloud.webapi.service

import com.trevorism.data.PingingDatastoreRepository
import com.trevorism.data.Repository
import com.trevorism.data.model.filtering.FilterBuilder
import com.trevorism.data.model.filtering.SimpleFilter
import com.trevorism.gcloud.webapi.model.Identity
import com.trevorism.gcloud.webapi.model.SaltedPassword
import com.trevorism.gcloud.webapi.model.User
import com.trevorism.https.DefaultInternalTokenSecureHttpClient

import java.time.Instant
import java.time.ZoneId
import java.util.logging.Logger

class DefaultUserCredentialService implements UserCredentialService {

    private Repository<User> repository = new PingingDatastoreRepository<>(User, new DefaultInternalTokenSecureHttpClient())
    private Emailer emailer = new Emailer()
    private static final Logger log = Logger.getLogger(DefaultUserCredentialService.class.name)

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
            log.warning("Registration missing a required field")
            return false
        }
        if (user.username.length() < 3 || user.password.length() < 6) {
            log.warning("Registration username/password length not acceptable")
            return false
        }
        if (!user.email.contains("@")) {
            log.warning("Email is not formatted correctly")
            return false
        }
        if (getUserCredential(user.username)) {
            log.warning("Registration detected duplicate username")
            return false
        }
        return true
    }

    @Override
    boolean activateUser(User user, boolean admin) {
        User toUpdate = getIdentity(user.identifer) as User
        toUpdate.active = true
        toUpdate.admin = admin
        toUpdate.dateExpired = Instant.now().atZone(ZoneId.systemDefault()).toLocalDateTime().plusYears(1).toDate()
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
        user.dateExpired = Instant.now().atZone(ZoneId.systemDefault()).toLocalDateTime().plusYears(1).toDate()

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
        user.dateExpired = Instant.now().atZone(ZoneId.systemDefault()).toLocalDateTime().plusDays(1).toDate()
        repository.update(user.id, user)

        emailer.sendForgotPasswordEmail(user.email, newPassword)
    }

    private User getUserCredential(String username) {
        try{
            return repository.filter(new FilterBuilder().addFilter(new SimpleFilter("username", "=", username.toLowerCase())).build())[0]
        }catch(Exception e){
            log.severe("Unable to retrieve user credentials from database for user: ${username} with message: ${e.message}")
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
