package com.trevorism.auth.service

interface UserCredentialService extends CredentialValidator {

    com.trevorism.auth.model.User getUser(String username)
    com.trevorism.auth.model.User deleteUser(String id)
    List<com.trevorism.auth.model.User> listUsers()

    com.trevorism.auth.model.User registerUser(com.trevorism.auth.model.User user)
    boolean validateRegistration(com.trevorism.auth.model.User user)

    boolean activateUser(com.trevorism.auth.model.User user, boolean isAdmin)
    boolean deactivateUser(com.trevorism.auth.model.User user)

    boolean changePassword(com.trevorism.auth.model.Identity identity, String currentPassword, String newPassword)
    void forgotPassword(com.trevorism.auth.model.Identity identity)
}
