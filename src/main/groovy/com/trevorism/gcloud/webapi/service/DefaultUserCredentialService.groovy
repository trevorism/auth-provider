package com.trevorism.gcloud.webapi.service

import com.trevorism.data.PingingDatastoreRepository
import com.trevorism.data.Repository
import com.trevorism.gcloud.webapi.model.Identity
import com.trevorism.gcloud.webapi.model.SaltedPassword
import com.trevorism.gcloud.webapi.model.User

import java.time.Instant
import java.time.ZoneId

class DefaultUserCredentialService implements UserCredentialService{

    private Repository<User> repository = new PingingDatastoreRepository<>(User)
    private Emailer emailer = new Emailer()

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

        user.active = true
        user.dateCreated = new Date()
        user.dateExpired = Instant.now().atZone(ZoneId.systemDefault()).toLocalDateTime().plusYears(1).toDate()

        User secureUser = setPasswordAndSalt(user)
        User createdUser = repository.create(secureUser)
        return cleanUser(createdUser)
    }

    @Override
    boolean validateCredentials(String username, String password) {
        User user = getUserCredential(username)

        if(!user || !user.username || !user.password || !user.salt || !user.active || HashUtils.isExpired(user.dateExpired)){
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

    @Override
    boolean activateUser(User user) {
        User toUpdate = getIdentity(user.identifer)
        toUpdate.active = true
        return repository.update(toUpdate.id, toUpdate)
    }

    @Override
    boolean deactivateUser(User user) {
        User toUpdate = getIdentity(user.identifer)
        toUpdate.active = false
        return repository.update(toUpdate.id, toUpdate)
    }

    @Override
    boolean changePassword(Identity identity, String currentPassword, String newPassword) {
        User user = getUserCredential(identity.getIdentifer())
        if(!validatePasswordsMatch(user, currentPassword)){
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
        if(!user){
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
        return repository.list().find{
            it.username == username
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
