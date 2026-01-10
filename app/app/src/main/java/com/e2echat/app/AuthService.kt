package com.e2echat.app

import android.util.Log

class AuthService(private val apiService: ApiService, private val cryptoService: CryptoService) {
    suspend fun register(username: String): Exception? {
        val keyBundle = cryptoService.generateX3DHKeyBundle()

        val prekeys = mutableListOf<String>().apply {
            add(keyBundle.signedPreKey)
            add(keyBundle.signedPreKeySignature)
            addAll(keyBundle.oneTimePreKeys)
        }.toTypedArray()

        val response = apiService.register(
            ApiService.RegisterRequest(
                username = username,
                masterPublicKey = keyBundle.identityKey,
                masterSignedPublicKey = keyBundle.signedPreKey,
                prekeys = prekeys
            )
        )
        if (response.isSuccessful) {
            Log.d("API", "Registration successful")
            return null
        } else {
            cryptoService.deleteAllKeys()
            Log.e("API", "Registration failed with code ${response.code()}")
            return Exception("Registration failed with code ${response.code()}")
        }
    }
}