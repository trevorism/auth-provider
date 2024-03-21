package com.trevorism.auth.service

import com.trevorism.auth.bean.GenerateTokenSecureHttpClientProvider
import com.trevorism.auth.errors.AuthException
import com.trevorism.auth.model.*
import com.trevorism.data.FastDatastoreRepository
import com.trevorism.data.Repository
import com.trevorism.data.model.filtering.FilterBuilder
import com.trevorism.data.model.filtering.SimpleFilter
import com.trevorism.https.SecureHttpClient
import com.trevorism.secure.Roles
import io.micronaut.security.authentication.Authentication
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.time.Instant
import java.time.temporal.ChronoUnit

@jakarta.inject.Singleton
class DefaultUserCredentialService implements UserCredentialService {

    private static final Logger log = LoggerFactory.getLogger(DefaultUserCredentialService)
    private Repository<User> repository
    private Emailer emailer

    DefaultUserCredentialService(SecureHttpClient httpClient) {
        repository = new FastDatastoreRepository<>(User, httpClient)
        emailer = new Emailer()
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
    User registerUser(RegistrationRequest request) {
        this.repository = new FastDatastoreRepository<>(User, new GenerateTokenSecureHttpClientProvider(request.tenantGuid, request.audience).secureHttpClient)

        if (!validateRegistration(request)) {
            throw new AuthException("Unable to register user")
        }

        User user = request.toUser()

        //Disallow auto registration for non-tenant users
        if (!request.tenantGuid) {
            user.active = false
        }

        user.dateCreated = new Date()
        if (user.isActive()) {
            user.dateExpired = Date.from(Instant.now().plus(365, ChronoUnit.DAYS))
        }

        user.username = user.username.toLowerCase()
        User secureUser = setPasswordAndSalt(user)
        User createdUser = repository.create(secureUser)
        emailer.sendRegistrationEmailToNotifySiteAdmin(user.username, user.email, user.tenantGuid)
        return cleanUser(createdUser)
    }

    @Override
    boolean validateCredentials(TokenRequest tokenRequest) {
        String username = tokenRequest?.id
        String password = tokenRequest?.password

        if (!username || !password) {
            return false
        }

        this.repository = new FastDatastoreRepository<>(User, new GenerateTokenSecureHttpClientProvider(tokenRequest.tenantGuid, tokenRequest.audience).secureHttpClient)
        User user = getUserByUsername(username)

        if (!user || !user.username || !user.password || !user.salt || !user.active || HashUtils.isExpired(user.dateExpired)) {
            return false
        }

        return validatePasswordsMatch(user, password)
    }

    @Override
    Identity getIdentity(String identifier) {
        getUserByUsername(identifier)
    }

    @Override
    boolean validateRegistration(RegistrationRequest request) {
        if (!request || !request.username || !request.password || !request.email) {
            log.warn("Registration missing a required field")
            return false
        }
        if (request.username.length() < 3 || request.password.length() < 6) {
            log.warn("Registration username/password length not acceptable")
            return false
        }
        if (!request.email.contains("@")) {
            log.warn("Email is not formatted correctly")
            return false
        }
        if (userMatchesCurrentUsers(request)) {
            log.warn("Registration detected duplicate username or email")
            return false
        }
        return true
    }

    @Override
    boolean activateUser(ActivationRequest activationRequest, Authentication authentication) {
        validateActivationRequest(authentication, activationRequest)
        this.repository = new FastDatastoreRepository<>(User, new GenerateTokenSecureHttpClientProvider(activationRequest.tenantGuid, null).secureHttpClient)

        User toUpdate = getUserByUsername(activationRequest.getUsername())
        toUpdate.active = true
        toUpdate.admin = activationRequest.isAdmin
        toUpdate.dateExpired = Date.from(Instant.now().plus(365, ChronoUnit.DAYS))
        def result = repository.update(toUpdate.id, toUpdate)
        if (result) {
            if (!activationRequest.doNotSendWelcomeEmail) {
                emailer.sendActivationEmail(toUpdate.email)
            }
            return true
        }
        return false
    }

    private static void validateActivationRequest(Authentication authentication, ActivationRequest activationRequest) {
        String role = authentication.getRoles().first().toString()
        if (role != Roles.ADMIN && activationRequest.isAdmin) {
            throw new AuthException("User is not authorized to activate an admin user")
        }
        String tenant = authentication.getAttributes().get("tenant")
        if (tenant && tenant != activationRequest.tenantGuid) {
            throw new AuthException("Tenant Admins may only activate users for their tenant")
        }
    }

    @Override
    boolean deactivateUser(User user) {
        User toUpdate = getIdentity(user.identifer) as User
        toUpdate.active = false
        return repository.update(toUpdate.id, toUpdate)
    }

    @Override
    boolean changePassword(ChangePasswordRequest changePasswordRequest, Authentication authentication) {
        User user = getUserForPasswordChange(changePasswordRequest, authentication)
        if (!validatePasswordsMatch(user, changePasswordRequest.currentPassword)) {
            return false
        }
        user.password = changePasswordRequest.desiredPassword
        user = setPasswordAndSalt(user)
        user.dateExpired = Date.from(Instant.now().plus(365, ChronoUnit.DAYS))

        repository.update(user.id, user)
    }

    @Override
    void forgotPassword(ForgotPasswordRequest forgotPasswordRequest) {
        this.repository = new FastDatastoreRepository<>(User, new GenerateTokenSecureHttpClientProvider(forgotPasswordRequest.tenantGuid, forgotPasswordRequest.audience).secureHttpClient)

        User user = getUserByUsername(forgotPasswordRequest.username)
        if (!user) {
            throw new AuthException("Unable to locate user: ${forgotPasswordRequest.username}")
        }
        String newPassword = HashUtils.generateRawSecret()
        user.password = newPassword
        user = setPasswordAndSalt(user)
        user.dateExpired = Date.from(Instant.now().plus(1, ChronoUnit.DAYS))
        repository.update(user.id, user)

        emailer.sendForgotPasswordEmail(user.email, newPassword, forgotPasswordRequest.audience)
    }

    @Override
    User getCurrentUser(Authentication authentication) {
        String id = authentication.getAttributes().get("id")
        return getUser(id)
    }

    private User getUserByUsername(String username) {
        try {
            return repository.filter(new FilterBuilder().addFilter(new SimpleFilter("username", "=", username.toLowerCase())).build())[0]
        } catch (Exception e) {
            log.error("Unable to retrieve user credentials from database for user: ${username} with message: ${e.message}")
            return null
        }
    }

    private boolean userMatchesCurrentUsers(RegistrationRequest request) {
        List<User> allUsers = repository.list()
        return allUsers.any { it.username.toLowerCase() == request.username.toLowerCase() || it.email.toLowerCase() == request.email.toLowerCase() }
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

    User getUserForPasswordChange(ChangePasswordRequest changePasswordRequest, Authentication authentication) {
        if(changePasswordRequest.tenantGuid){
            this.repository = new FastDatastoreRepository<>(User, new GenerateTokenSecureHttpClientProvider(changePasswordRequest.tenantGuid, changePasswordRequest.audience).secureHttpClient)
        }

        if(authentication.getAttributes().get("id")){
            return getCurrentUser(authentication)
        }

        return getUserByUsername(changePasswordRequest.username)
    }
}
