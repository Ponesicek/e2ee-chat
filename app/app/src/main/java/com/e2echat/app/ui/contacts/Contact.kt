package com.e2echat.app.ui.contacts

data class Contact(
    val id: String,
    val name: String,
    val status: String = "Hey there! I am using E2EChat",
    val avatarInitial: Char = name.firstOrNull()?.uppercaseChar() ?: '?',
    val isOnline: Boolean = false,
    val lastSeen: String = ""
)
