package com.trevorism.auth.service.oauth

import com.trevorism.auth.model.Oauth2Tokens
import io.jsonwebtoken.Claims
import io.jsonwebtoken.Jws

interface Oauth2Parser {

    Jws<Claims> parse(Oauth2Tokens tokens)
}