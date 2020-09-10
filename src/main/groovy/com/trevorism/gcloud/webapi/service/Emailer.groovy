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

    void sendForgotPasswordEmail(String emailAddress, String newPassword){
        Email email = new Email(recipients: emailAddress, subject: "Trevorism: Forgot Password", body: buildBody(newPassword))
        eventProducer.sendEvent("email", email)
    }

    private static String buildBody(String password) {
        StringBuilder sb = new StringBuilder()
        sb << "Your new password for trevorism.com is: ${password}\n"
        sb << "It will expire in 1 day."
        return sb.toString()
    }

}
