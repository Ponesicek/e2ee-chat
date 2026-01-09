package com.e2echat.app

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PublicKey

class CryptoService() {

    suspend fun deleteMasterKeyPair() {
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(MASTER_KEY_ALIAS)
    }
    suspend fun generateMasterKeyPair(): String = withContext(Dispatchers.IO) {
        val existingPublic = loadKeyPair()
        if (existingPublic != null) {
            return@withContext Base64.encodeToString(existingPublic.encoded, Base64.NO_WRAP)
        }

        val kpg: KeyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            "AndroidKeyStore"
        )

        val parameterSpec = KeyGenParameterSpec.Builder(
            MASTER_KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        ).apply {
            setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            setKeySize(256)
        }.build()

        kpg.initialize(parameterSpec)
        val kp = kpg.generateKeyPair()

        Base64.encodeToString(kp.public.encoded, Base64.NO_WRAP)
    }

    suspend fun loadKeyPair(): PublicKey? {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

        val entry = keyStore.getEntry(MASTER_KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry
        return entry?.certificate?.publicKey
    }

    suspend fun encryptMessage(message: String, recipientUsername: String, publicKey: String): String = withContext(Dispatchers.IO) {

        // 3. Load the recipient's public key
        val recipientPublicKeyBytes: ByteArray = Base64.decode(publicKey, Base64.NO_WRAP)

        // TODO: Convert the EC public key to a Tink-compatible format
        // This requires creating a Tink keyset from the raw public key bytes
        // For now, this is a placeholder that needs proper implementation

        // 4. Encrypt the message
        val payload = message.toByteArray()
        // val hybridEncrypt = ... // Create HybridEncrypt primitive from the public key
        // val ciphertext = hybridEncrypt.encrypt(payload, null)

        // Return base64 encoded ciphertext
        Base64.encodeToString(payload, Base64.NO_WRAP) // Placeholder - replace with actual encryption
    }
    private final val MASTER_KEY_ALIAS = "Master"
}