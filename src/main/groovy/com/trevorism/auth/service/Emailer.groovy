package com.trevorism.auth.service

import com.trevorism.EmailClient
import com.trevorism.https.InternalTokenSecureHttpClient
import com.trevorism.model.Email

class Emailer {

    private EmailClient emailClient

    Emailer() {
        emailClient = new EmailClient(new InternalTokenSecureHttpClient())
    }

    boolean sendForgotPasswordEmail(String emailAddress, String newPassword) {
        Email email = new Email(recipients: [emailAddress], subject: "Trevorism: Forgot Password", body: buildBody(newPassword))
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

    private static String buildBody(String password) {
        StringBuilder sb = new StringBuilder()
        sb << "Your new password for trevorism.com is: ${password}\n"
        sb << "It will expire in 1 day. Change your password here: https://www.trevorism.com/change"
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
