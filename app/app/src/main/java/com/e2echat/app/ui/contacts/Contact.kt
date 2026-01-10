package com.e2echat.app.ui.contacts

import java.util.UUID

data class Contact(
    val id: String = UUID.randomUUID().toString(),
    val name: String,
    val lastMessage: String = ""
)
