package com.trevorism.auth.controller

import io.micronaut.http.HttpResponse
import io.micronaut.http.annotation.Controller
import io.micronaut.http.annotation.Get
import io.swagger.v3.oas.annotations.Operation
import io.swagger.v3.oas.annotations.responses.ApiResponse
import io.swagger.v3.oas.annotations.tags.Tag

@Controller("/_ah")
class WarmupController {
    @Tag(name = "Root Operations")
    @Operation(summary = "Warmup")
    @ApiResponse(responseCode = "200")
    @Get(value = "/warmup")
    HttpResponse warmup() {
        return HttpResponse.ok()
    }
}
