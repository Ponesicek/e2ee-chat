package com.e2echat.app

import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.Headers
import retrofit2.http.POST

interface ApiService {
    data class RegisterRequest(
        val username: String,
        val publicKey: String
    )
    @Headers("Content-Type: application/json")
    @POST("register")
    suspend fun register(@Body registerRequest: RegisterRequest): Response<String>
}