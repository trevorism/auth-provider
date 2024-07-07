package com.trevorism.auth.service

import com.trevorism.EmailClient
import com.trevorism.auth.bean.TenantTokenSecureHttpClientProvider
import com.trevorism.model.Email

@jakarta.inject.Singleton
class Emailer {

    private EmailClient emailClient

    Emailer(TenantTokenSecureHttpClientProvider generateTokenSecureHttpClientProvider) {
        emailClient = new EmailClient(generateTokenSecureHttpClientProvider.getSecureHttpClient(null,null))
    }

    boolean sendForgotPasswordEmail(String emailAddress, String username, String newPassword, String audience) {
        Email email = new Email(recipients: [emailAddress], subject: "${audience}: Reset Password", body: buildResetPasswordBody(username, newPassword, audience))
        emailClient.sendEmail(email)
    }

    boolean sendActivationEmail(String emailAddress) {
        Email email = new Email(recipients: [emailAddress], subject: "Trevorism: Activation", body: buildActivationBody())
        emailClient.sendEmail(email)
    }

    boolean sendRegistrationEmailToNotifySiteAdmin(String username, String emailAddress, String tenantGuid) {
        Email email = new Email(recipients: ["feedback@trevorism.com"], subject: "Trevorism: Registration", body: buildRegistrationBody(username, emailAddress, tenantGuid))
        emailClient.sendEmail(email)
    }

    private static String buildResetPasswordBody(String username, String password, String audience) {
        StringBuilder sb = new StringBuilder()
        sb << "A reset password request has been made for your ${username} account on ${audience}\n\n"
        sb << "Your new password for is: ${password}\n\n"
        sb << "It will expire in 1 day. Change your password here: https://${audience}/change"
        return sb.toString()
    }

    private static String buildActivationBody() {
        StringBuilder sb = new StringBuilder()
        sb << "Congratulations your account has been activated!\n"
        sb << "Login to https://trevorism.com"
        return sb.toString()
    }

    private static String buildRegistrationBody(String username, String email, String tenantGuid) {
        String base = "User: ${username} with email: ${email} is requesting activation"
        if (tenantGuid) {
            base << " for tenant: ${tenantGuid}"
        }
        return base
    }

}
