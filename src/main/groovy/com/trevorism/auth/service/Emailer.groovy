package com.trevorism.auth.service

import com.trevorism.EmailClient
import com.trevorism.auth.bean.TenantTokenSecureHttpClientProvider
import com.trevorism.auth.model.Tenant
import com.trevorism.data.FastDatastoreRepository
import com.trevorism.data.Repository
import com.trevorism.data.model.filtering.FilterConstants
import com.trevorism.data.model.filtering.SimpleFilter
import com.trevorism.https.SecureHttpClient
import com.trevorism.model.Email

@jakarta.inject.Singleton
class Emailer {

    private EmailClient emailClient
    private Repository<Tenant> tenantRepository

    Emailer(TenantTokenSecureHttpClientProvider generateTokenSecureHttpClientProvider) {
        SecureHttpClient secureHttpClient = generateTokenSecureHttpClientProvider.getSecureHttpClient(null, null)
        emailClient = new EmailClient(secureHttpClient)
        tenantRepository = new FastDatastoreRepository<>(Tenant, secureHttpClient)
    }

    boolean sendForgotPasswordEmail(String emailAddress, String username, String newPassword, String audience) {
        Email email = new Email(recipients: [emailAddress], subject: "${audience}: Reset Password", body: buildResetPasswordBody(username, newPassword, audience))
        emailClient.sendEmail(email)
    }

    boolean sendActivationEmail(String emailAddress, String tenantGuid) {
        String domain = fetchDomainFromTenantGuid(tenantGuid)
        String domainString = domain != "trevorism.com" ? domain : "Trevorism"
        Email email = new Email(recipients: [emailAddress], subject: "${domainString}: Activation", body: buildActivationBody(domain))
        emailClient.sendEmail(email)
    }

    private String fetchDomainFromTenantGuid(String tenantGuid) {
        def tenantList = tenantRepository.filter(new SimpleFilter("guid" , FilterConstants.OPERATOR_EQUAL, tenantGuid))
        if(tenantList){
            return tenantList[0].domain
        }
        return "trevorism.com"
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

    private static String buildActivationBody(String domain) {
        StringBuilder sb = new StringBuilder()
        sb << "Congratulations your account has been activated!\n"
        sb << "Login to https://${domain}"
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
