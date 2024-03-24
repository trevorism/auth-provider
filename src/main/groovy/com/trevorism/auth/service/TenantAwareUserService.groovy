package com.trevorism.auth.service

import com.trevorism.auth.bean.TenantTokenSecureHttpClientProvider
import com.trevorism.auth.errors.AuthException
import com.trevorism.auth.model.ActivationRequest
import com.trevorism.auth.model.ChangePasswordRequest
import com.trevorism.auth.model.ForgotPasswordRequest
import com.trevorism.auth.model.Identity
import com.trevorism.auth.model.RegistrationRequest
import com.trevorism.auth.model.SaltedPassword
import com.trevorism.auth.model.TokenRequest
import com.trevorism.auth.model.User
import com.trevorism.data.FastDatastoreRepository
import com.trevorism.data.Repository
import com.trevorism.data.model.filtering.FilterBuilder
import com.trevorism.data.model.filtering.SimpleFilter
import com.trevorism.secure.Roles
import io.micronaut.security.authentication.Authentication
import jakarta.inject.Inject
import org.slf4j.Logger
import org.slf4j.LoggerFactory

import java.time.Instant
import java.time.temporal.ChronoUnit

@jakarta.inject.Singleton
class TenantAwareUserService implements TenantUserService{

    private static final Logger log = LoggerFactory.getLogger(TenantAwareUserService)

    @Inject
    private Emailer emailer

    @Inject
    TenantTokenSecureHttpClientProvider generateTokenSecureHttpClientProvider

    @Override
    User registerUser(RegistrationRequest request){
        Repository<User> repository = new FastDatastoreRepository<>(User, generateTokenSecureHttpClientProvider.getSecureHttpClient(request.tenantGuid, request.audience))

        if (!validateRegistration(repository, request)) {
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
    User forgotPassword(ForgotPasswordRequest forgotPasswordRequest){
        Repository<User> repository = new FastDatastoreRepository<>(User, generateTokenSecureHttpClientProvider.getSecureHttpClient(forgotPasswordRequest.tenantGuid, forgotPasswordRequest.audience))

        User user = getUserByUsername(repository, forgotPasswordRequest.username)
        if (!user) {
            throw new AuthException("Unable to locate user: ${forgotPasswordRequest.username}")
        }
        String newPassword = HashUtils.generateRawSecret()
        user.password = newPassword
        user = setPasswordAndSalt(user)
        user.dateExpired = Date.from(Instant.now().plus(1, ChronoUnit.DAYS))
        User updatedUser = repository.update(user.id, user)

        emailer.sendForgotPasswordEmail(user.email, user.username, newPassword, forgotPasswordRequest.audience ?: "trevorism.com")
        return cleanUser(updatedUser)
    }

    @Override
    boolean activateUser(ActivationRequest activationRequest, Authentication authentication) {
        validateActivationRequest(authentication, activationRequest)
        Repository<User> repository = new FastDatastoreRepository<>(User, generateTokenSecureHttpClientProvider.getSecureHttpClient(activationRequest.tenantGuid, null))
        User toUpdate = getUserByUsername(repository, activationRequest.getUsername())

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

    @Override
    boolean deactivateUser(ActivationRequest activationRequest, Authentication authentication) {
        validateActivationRequest(authentication, activationRequest)
        Repository<User> repository = new FastDatastoreRepository<>(User, generateTokenSecureHttpClientProvider.getSecureHttpClient(activationRequest.tenantGuid, null))
        User toUpdate = getUserByUsername(repository, activationRequest.getUsername())
        toUpdate.active = false
        return repository.update(toUpdate.id, toUpdate)
    }

    @Override
    boolean validateCredentials(TokenRequest tokenRequest) {
        String username = tokenRequest?.id
        String password = tokenRequest?.password

        if (!username || !password) {
            return false
        }

        Repository<User> repository = new FastDatastoreRepository<>(User, generateTokenSecureHttpClientProvider.getSecureHttpClient(tokenRequest.tenantGuid, tokenRequest.audience))
        User user = getUserByUsername(repository, username)

        if (!user || !user.username || !user.password || !user.salt || !user.active || HashUtils.isExpired(user.dateExpired)) {
            return false
        }

        return validatePasswordsMatch(user, password)
    }

    @Override
    User getCurrentUser(Authentication authentication) {
        String id = authentication.getAttributes().get("id")
        String tenant = authentication.getAttributes().get("tenant")
        Repository<User> repository = new FastDatastoreRepository<>(User, generateTokenSecureHttpClientProvider.getSecureHttpClient(tenant, null))
        return repository.get(id)
    }

    @Override
    boolean changePassword(ChangePasswordRequest changePasswordRequest) {
        Repository<User> repository = new FastDatastoreRepository<>(User, generateTokenSecureHttpClientProvider.getSecureHttpClient(changePasswordRequest.tenantGuid, changePasswordRequest.audience))
        User user = getUserByUsername(repository, changePasswordRequest.username)

        if (!validatePasswordsMatch(user, changePasswordRequest.currentPassword)) {
            return false
        }
        user.password = changePasswordRequest.desiredPassword
        user = setPasswordAndSalt(user)
        user.dateExpired = Date.from(Instant.now().plus(365, ChronoUnit.DAYS))

        User updatedUser = repository.update(user.id, user)
        return updatedUser
    }

    @Override
    Identity getIdentity(TokenRequest tokenRequest) {
        Repository<User> repository = new FastDatastoreRepository<>(User, generateTokenSecureHttpClientProvider.getSecureHttpClient(tokenRequest.tenantGuid, tokenRequest.audience))
        return getUserByUsername(repository, tokenRequest.id)
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

    private static boolean validatePasswordsMatch(User user, String password) {
        SaltedPassword sp = new SaltedPassword(user.salt, user.password)
        return HashUtils.validatePasswordsMatch(sp, password)
    }

    private static User setPasswordAndSalt(User user) {
        SaltedPassword sp = HashUtils.createPasswordAndSalt(user.password)
        user.salt = sp.salt
        user.password = sp.password
        return user
    }

    private static boolean userMatchesCurrentUsers(Repository<User> repository, RegistrationRequest request) {
        List<User> allUsers = repository.list()
        return allUsers.any { it.username.toLowerCase() == request.username.toLowerCase() || it.email.toLowerCase() == request.email.toLowerCase() }
    }

    private static User cleanUser(User user) {
        user?.password = null
        user?.salt = null
        return user
    }

    private static User getUserByUsername(Repository<User> repository, String username) {
        try {
            return repository.filter(new FilterBuilder().addFilter(new SimpleFilter("username", "=", username.toLowerCase())).build())[0]
        } catch (Exception e) {
            log.error("Unable to retrieve user credentials from database for user: ${username} with message: ${e.message}")
            return null
        }
    }

    private static boolean validateRegistration(Repository<User> repository, RegistrationRequest request){
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
        if (userMatchesCurrentUsers(repository, request)) {
            log.warn("Registration detected duplicate username or email")
            return false
        }
        return true
    }
}
