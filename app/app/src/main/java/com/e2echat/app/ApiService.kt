package com.e2echat.app

import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Query

interface ApiService {
    data class RegisterRequest(
        val username: String,
        val masterPublicKey: String,
        val masterSignedPublicKey: String,
        val prekeys: Array<String> = arrayOf(),
    )

    @Headers("Content-Type: application/json")
    @POST("register")
    suspend fun register(@Body registerRequest: RegisterRequest): Response<String>

    @GET("publickey")
    suspend fun getPublicKey(@Query("username") username: String): Response<String>
}