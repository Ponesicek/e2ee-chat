package com.e2echat.app

import android.util.Log

class AuthService(
    private val apiService: ApiService,
    private val cryptoService: CryptoService,
) {

    suspend fun register(username: String): Exception? {
        val keyBundle = cryptoService.generateX3DHKeyBundle()
        val request = ApiService.RegisterRequest(
            username = username,
            masterPublicKey = keyBundle.identityKey,
            prekeys = toPrekeyArray(keyBundle),
        )

        val response = apiService.register(request)
        if (response.isSuccessful) {
            Log.d("API", "Registration successful")
            return null
        }

        cryptoService.deleteAllKeys()
        Log.e("API", "Registration failed with code ${response.code()}")
        return Exception("Registration failed with code ${response.code()}")
    }

    private fun toPrekeyArray(keyBundle: X3DHKeyBundle): Array<String> {
        return buildList {
            add(keyBundle.signedPreKey)
            add(keyBundle.signedPreKeySignature)
            addAll(keyBundle.oneTimePreKeys)
        }.toTypedArray()
    }
}
