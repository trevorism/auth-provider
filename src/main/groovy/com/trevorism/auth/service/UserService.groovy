package com.trevorism.auth.service

import com.trevorism.auth.model.Identity
import com.trevorism.auth.model.User


interface UserService {

    User getUser(String id)
    List<User> listUsers()
    User deleteUser(String id)
    Identity getIdentity(String identifier)

}
