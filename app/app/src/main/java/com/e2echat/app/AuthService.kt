package com.e2echat.app

import android.util.Log
import androidx.annotation.Nullable

class AuthService(private val apiService: ApiService, private val cryptoService: CryptoService) {
    suspend fun register(username: String): Exception? {
        val response = apiService.register(
            ApiService.RegisterRequest(
                username,
                cryptoService.generateMasterKeyPair()
            )
        )
        if (response.isSuccessful) {
            Log.d("API", "Registration successful")
            return null;
        } else {
            cryptoService.deleteMasterKeyPair()
            Log.e("API", "Registration failed with code ${response.code()}")
            return Exception("Registration failed with code ${response.code()}")
        }
    }

}