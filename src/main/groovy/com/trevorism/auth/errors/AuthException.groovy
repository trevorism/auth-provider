package com.trevorism.auth.errors

class AuthException extends RuntimeException{
    AuthException(String message) {
        super(message)
    }
}
