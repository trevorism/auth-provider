package com.trevorism.gcloud.webapi.service

import com.trevorism.event.EventProducer
import com.trevorism.event.PingingEventProducer

class Emailer {

    private EventProducer<Email> eventProducer = new PingingEventProducer<>()

    class Email {
        String recipients
        String subject
        String body
    }

    void sendForgotPasswordEmail(String emailAddress, String newPassword) {
        Email email = new Email(recipients: emailAddress, subject: "Trevorism: Forgot Password", body: buildBody(newPassword))
        eventProducer.sendEvent("email", email)
    }

    void sendActivationEmail(String emailAddress) {
        Email email = new Email(recipients: emailAddress, subject: "Trevorism: Activation", body: buildActivationBody())
        eventProducer.sendEvent("email", email)
    }

    void sendRegistrationEmail(String username, String emailAddress) {
        Email email = new Email(recipients: "feedback@trevorism.com", subject: "Trevorism: Registration", body: buildRegistrationBody(username, emailAddress))
        eventProducer.sendEvent("email", email)
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

    private static String buildRegistrationBody(String username, String email) {
        return "User: ${username} with email: ${email} is requesting activation"
    }

}
