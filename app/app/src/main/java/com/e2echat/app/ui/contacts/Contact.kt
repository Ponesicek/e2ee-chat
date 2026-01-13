package com.e2echat.app.ui.contacts

import java.util.UUID

data class Contact(
    val id: String = UUID.randomUUID().toString(),
    val name: String,
    val lastMessage: String = "",
    val identityKey: String? = null,
    val signedPreKey: String? = null,
    val signedPreKeySignature: String? = null,
    val oneTimePreKey: String? = null,
    val preKeyId: String? = null,
    val hasSession: Boolean = false
)
