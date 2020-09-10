package com.trevorism.gcloud.webapi.service

import com.trevorism.event.EventhubProducer
import org.junit.Test

class EmailerTest {

    @Test
    void testSendForgotPasswordEmail() {
        Emailer emailer = new Emailer()
        emailer.eventProducer = new EventhubProducer<Emailer.Email>() {
            @Override
            void sendEvent(String topic, Emailer.Email event) {
                assert topic == "email"
            }

            @Override
            void sendEvent(String topic, Emailer.Email event, String correlationId) {
                assert topic == "email"
            }

            @Override
            void validateTopic(String topic) {
                assert topic == "email"
            }
        }

        emailer.sendForgotPasswordEmail("trevorism@gmail.com", "12345678")
    }
}
