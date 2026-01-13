package com.e2echat.app

import android.content.Context
import android.util.Log
import androidx.core.content.edit

class AuthService(
    private val context: Context,
    private val apiService: ApiService,
    private val cryptoService: CryptoService,
) {
    private val prefs by lazy { 
        context.getSharedPreferences("auth_prefs", Context.MODE_PRIVATE) 
    }

    suspend fun register(username: String): Exception? {
        val keyBundle = cryptoService.generateX3DHKeyBundle()
        val request = ApiService.RegisterRequest(
            username = username,
            masterPublicKey = keyBundle.identityKey,
            prekeys = toPrekeyArray(keyBundle),
        )

        val response = apiService.register(request)
        if (response.isSuccessful) {
            prefs.edit { putString(KEY_USERNAME, username) }
            Log.d("API", "Registration successful")
            return null
        }

        cryptoService.deleteAllKeys()
        Log.e("API", "Registration failed with code ${response.code()}")
        return Exception("Registration failed with code ${response.code()}")
    }

    fun getUsername(): String? = prefs.getString(KEY_USERNAME, null)

    private fun toPrekeyArray(keyBundle: X3DHKeyBundle): Array<String> {
        return buildList {
            add(keyBundle.signedPreKey)
            add(keyBundle.signedPreKeySignature)
            addAll(keyBundle.oneTimePreKeys)
        }.toTypedArray()
    }

    companion object {
        private const val KEY_USERNAME = "username"
    }
}
