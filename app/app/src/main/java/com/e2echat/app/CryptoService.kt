package com.e2echat.app

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec

data class X3DHKeyBundle(
    val identityKey: String,
    val signedPreKey: String,
    val signedPreKeySignature: String,
    val oneTimePreKeys: List<String>
)

class CryptoService() {
    private val IDENTITY_KEY_ALIAS = "IdentityKey"
    private val SIGNED_PREKEY_ALIAS = "SignedPreKey"
    private val ONE_TIME_PREKEY_ALIAS_PREFIX = "OneTimePreKey_"
    private val NUM_ONE_TIME_PREKEYS = 8

    suspend fun deleteAllKeys() = withContext(Dispatchers.IO) {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        keyStore.deleteEntry(IDENTITY_KEY_ALIAS)
        keyStore.deleteEntry(SIGNED_PREKEY_ALIAS)
        for (i in 0 until NUM_ONE_TIME_PREKEYS) {
            keyStore.deleteEntry("$ONE_TIME_PREKEY_ALIAS_PREFIX$i")
        }
    }

    suspend fun generateX3DHKeyBundle(): X3DHKeyBundle = withContext(Dispatchers.IO) {
        val identityKey = generateOrLoadKeyPair(IDENTITY_KEY_ALIAS, forSigning = true)
        val signedPreKey = generateKeyPair(SIGNED_PREKEY_ALIAS, forSigning = false)
        val signedPreKeySignature = signData(
            IDENTITY_KEY_ALIAS,
            Base64.decode(signedPreKey, Base64.NO_WRAP)
        )
        val oneTimePreKeys = (0 until NUM_ONE_TIME_PREKEYS).map { i ->
            generateKeyPair("$ONE_TIME_PREKEY_ALIAS_PREFIX$i", forSigning = false)
        }

        X3DHKeyBundle(
            identityKey = identityKey,
            signedPreKey = signedPreKey,
            signedPreKeySignature = signedPreKeySignature,
            oneTimePreKeys = oneTimePreKeys
        )
    }

    private fun generateOrLoadKeyPair(alias: String, forSigning: Boolean): String {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val existingEntry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
        if (existingEntry != null) {
            return Base64.encodeToString(existingEntry.certificate.publicKey.encoded, Base64.NO_WRAP)
        }
        return generateKeyPair(alias, forSigning)
    }

    private fun generateKeyPair(alias: String, forSigning: Boolean): String {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        keyStore.deleteEntry(alias)

        val purposes = if (forSigning) {
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        } else {
            KeyProperties.PURPOSE_AGREE_KEY
        }

        val kpg = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            "AndroidKeyStore"
        )

        val builder = KeyGenParameterSpec.Builder(alias, purposes).apply {
            setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            if (forSigning) {
                setDigests(KeyProperties.DIGEST_SHA256)
            }
        }

        kpg.initialize(builder.build())
        val kp = kpg.generateKeyPair()

        return Base64.encodeToString(kp.public.encoded, Base64.NO_WRAP)
    }

    private fun signData(keyAlias: String, data: ByteArray): String {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val entry = keyStore.getEntry(keyAlias, null) as KeyStore.PrivateKeyEntry
        val privateKey = entry.privateKey

        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(privateKey)
        signature.update(data)
        val signatureBytes = signature.sign()

        return Base64.encodeToString(signatureBytes, Base64.NO_WRAP)
    }

    suspend fun getIdentityPublicKey(): String? = withContext(Dispatchers.IO) {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val entry = keyStore.getEntry(IDENTITY_KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry
        entry?.certificate?.publicKey?.let {
            Base64.encodeToString(it.encoded, Base64.NO_WRAP)
        }
    }

    suspend fun encryptMessage(message: String, recipientUsername: String, publicKey: String): String = withContext(Dispatchers.IO) {
        val recipientPublicKeyBytes: ByteArray = Base64.decode(publicKey, Base64.NO_WRAP)
        val payload = message.toByteArray()
        Base64.encodeToString(payload, Base64.NO_WRAP)
    }
}