package com.trevorism

import groovy.transform.CompileStatic
import io.micronaut.runtime.Micronaut
import io.swagger.v3.oas.annotations.OpenAPIDefinition
import io.swagger.v3.oas.annotations.info.Contact
import io.swagger.v3.oas.annotations.info.Info

@OpenAPIDefinition(
        info = @Info(
                title = "Auth",
                version = "1.2.0",
                description = "Trevorism authentication and authorization API",
                contact = @Contact(url = "https://trevorism.com", name = "Trevor Brooks", email = "tbrooks@trevorism.com")
        )
)
@CompileStatic
class Application {
    static void main(String[] args) {
        Micronaut.run(Application, args)
    }
}
