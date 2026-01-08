package com.e2echat.app

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.KeyPairGenerator
import java.security.KeyStore

class AuthService(private val apiService: ApiService) {
    suspend fun register(username: String) {
        try {
            val response = apiService.register(ApiService.RegisterRequest(username, generateKeyPair()))
            if (response.isSuccessful) {
                Log.d("API", "Registration successful")
            } else {
                Log.e("API", "Registration failed: ${response.code()}")
            }
        } catch (e: Exception) {
            Log.e("API", "Registration failed with catch: ${e.message}")
        }
    }

    suspend fun generateKeyPair(): String = withContext(Dispatchers.IO) {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

        val entry = keyStore.getEntry(KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry
        val existingPublic = entry?.certificate?.publicKey

        if (existingPublic != null) {
            return@withContext Base64.encodeToString(existingPublic.encoded, Base64.NO_WRAP)
        }

        val kpg: KeyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            "AndroidKeyStore"
        )

        val parameterSpec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        ).apply {
            setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            setKeySize(256)
        }.build()

        kpg.initialize(parameterSpec)
        val kp = kpg.generateKeyPair()

        Base64.encodeToString(kp.public.encoded, Base64.NO_WRAP)
    }

    companion object {
        private const val KEY_ALIAS = "SystemKey"
    }

}