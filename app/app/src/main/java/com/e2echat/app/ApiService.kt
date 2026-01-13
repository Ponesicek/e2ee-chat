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
        val prekeys: Array<String> = arrayOf(),
    )

    data class KeysResponse(
        val IdentityKey: String,
        val SignedPreKey: String,
        val SignedPreKeySignature: String,
        val OneTimePreKey: String,
        val PreKeyID: String
    )

    data class HandshakeBundleRequest(
        val recipientUsername: String,
        val senderUsername: String,
        val ephemeralKey: String,
        val identityKey: String,
        val usedOneTimePreKeyId: String?
    )

    data class HandshakeBundleResponse(
        val senderUsername: String,
        val ephemeralKey: String,
        val identityKey: String,
        val usedOneTimePreKeyId: String?
    )

    @Headers("Content-Type: application/json")
    @POST("register")
    suspend fun register(@Body registerRequest: RegisterRequest): Response<String>

    @Headers("Content-Type: application/json")
    @GET("getkeys")
    suspend fun getKeys(@Query("username") username: String): Response<KeysResponse>

    @Headers("Content-Type: application/json")
    @POST("handshake")
    suspend fun submitHandshake(@Body request: HandshakeBundleRequest): Response<String>

    @Headers("Content-Type: application/json")
    @GET("handshake")
    suspend fun getPendingHandshakes(@Query("username") username: String): Response<List<HandshakeBundleResponse>>
}