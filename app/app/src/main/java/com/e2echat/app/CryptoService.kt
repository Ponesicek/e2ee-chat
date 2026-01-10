package com.e2echat.app

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import androidx.core.content.edit

data class X3DHKeyBundle(
    val identityKey: String,
    val signedPreKey: String,
    val signedPreKeySignature: String,
    val oneTimePreKeys: List<String>
)

class CryptoService(context: Context) {

    private val prefsStore = PrefsKeyStore(context)
    private val keyGenerator = Curve25519KeyGenerator()
    private val signer = Ed25519Signature()

    suspend fun deleteAllKeys() = withContext(Dispatchers.IO) {
        prefsStore.clearAll()
    }

    suspend fun generateX3DHKeyBundle(): X3DHKeyBundle = withContext(Dispatchers.IO) {
        val identityPublicKey = prefsStore.getOrCreateKeyPair(
            alias = KeyAliases.IDENTITY,
            algorithm = KeyAlgorithm.Ed25519,
            keyGenerator = keyGenerator,
        )

        val signedPreKeyPublicKey = prefsStore.getOrCreateKeyPair(
            alias = KeyAliases.SIGNED_PREKEY,
            algorithm = KeyAlgorithm.X25519,
            keyGenerator = keyGenerator,
        )

        val signedPreKeySignature = signer.sign(
            privateKeyBytes = prefsStore.getPrivateKeyBytes(KeyAliases.IDENTITY),
            data = Base64.decode(signedPreKeyPublicKey, Base64.NO_WRAP),
        )

        val oneTimePreKeys = (0 until KeyAliases.NUM_ONE_TIME_PREKEYS).map { index ->
            prefsStore.getOrCreateKeyPair(
                alias = KeyAliases.oneTimePreKey(index),
                algorithm = KeyAlgorithm.X25519,
                keyGenerator = keyGenerator,
            )
        }

        X3DHKeyBundle(
            identityKey = identityPublicKey,
            signedPreKey = signedPreKeyPublicKey,
            signedPreKeySignature = signedPreKeySignature,
            oneTimePreKeys = oneTimePreKeys
        )
    }

    suspend fun getIdentityPublicKey(): String? = withContext(Dispatchers.IO) {
        prefsStore.getPublicKey(KeyAliases.IDENTITY)
    }

    suspend fun encryptMessage(
        message: String,
        recipientUsername: String,
        publicKey: String,
    ): String = withContext(Dispatchers.IO) {
        val recipientPublicKeyBytes: ByteArray = Base64.decode(publicKey, Base64.NO_WRAP)
        val payload = message.toByteArray()
        Base64.encodeToString(payload, Base64.NO_WRAP)
    }
}

private object KeyAliases {
    const val IDENTITY = "IdentityKey"
    const val SIGNED_PREKEY = "SignedPreKey"

    private const val ONE_TIME_PREKEY_ALIAS_PREFIX = "OneTimePreKey_"
    const val NUM_ONE_TIME_PREKEYS = 8

    fun oneTimePreKey(index: Int): String = "$ONE_TIME_PREKEY_ALIAS_PREFIX$index"
}

private enum class KeyAlgorithm {
    Ed25519,
    X25519,
}

private data class GeneratedKeyPair(
    val publicKeyBytes: ByteArray,
    val privateKeyBytes: ByteArray,
)

private class Curve25519KeyGenerator {
    private val secureRandom = SecureRandom()

    fun generate(algorithm: KeyAlgorithm): GeneratedKeyPair {
        return when (algorithm) {
            KeyAlgorithm.Ed25519 -> {
                val keyGen = Ed25519KeyPairGenerator().apply {
                    init(Ed25519KeyGenerationParameters(secureRandom))
                }
                val keyPair = keyGen.generateKeyPair()
                val privateKey = keyPair.private as Ed25519PrivateKeyParameters
                val publicKey = keyPair.public as Ed25519PublicKeyParameters
                GeneratedKeyPair(publicKey.encoded, privateKey.encoded)
            }

            KeyAlgorithm.X25519 -> {
                val keyGen = X25519KeyPairGenerator().apply {
                    init(X25519KeyGenerationParameters(secureRandom))
                }
                val keyPair = keyGen.generateKeyPair()
                val privateKey = keyPair.private as X25519PrivateKeyParameters
                val publicKey = keyPair.public as X25519PublicKeyParameters
                GeneratedKeyPair(publicKey.encoded, privateKey.encoded)
            }
        }
    }
}

private class Ed25519Signature {
    fun sign(privateKeyBytes: ByteArray, data: ByteArray): String {
        val signer = Ed25519Signer().apply {
            init(true, Ed25519PrivateKeyParameters(privateKeyBytes, 0))
        }
        signer.update(data, 0, data.size)
        val signatureBytes = signer.generateSignature()
        return Base64.encodeToString(signatureBytes, Base64.NO_WRAP)
    }
}

private class PrefsKeyStore(
    private val context: Context,
) {

    private val wrappingKeyStore = KeystoreAesGcm(
        alias = "CryptoServiceAES",
        provider = "AndroidKeyStore",
    )

    fun getPublicKey(alias: String): String? = prefs().getString(publicKeyPrefKey(alias), null)

    fun getPrivateKeyBytes(alias: String): ByteArray {
        val encryptedPrivateKeyBase64 = prefs().getString(privateKeyPrefKey(alias), null)
            ?: throw IllegalStateException("Missing private key for $alias")

        val ivBase64 = prefs().getString(ivPrefKey(alias), null)
            ?: throw IllegalStateException("Missing IV for $alias")

        return wrappingKeyStore.decrypt(
            ciphertext = Base64.decode(encryptedPrivateKeyBase64, Base64.NO_WRAP),
            iv = Base64.decode(ivBase64, Base64.NO_WRAP),
        )
    }

    fun getOrCreateKeyPair(
        alias: String,
        algorithm: KeyAlgorithm,
        keyGenerator: Curve25519KeyGenerator,
    ): String {
        val existingPublicKey = getPublicKey(alias)
        if (existingPublicKey != null) return existingPublicKey

        val generated = keyGenerator.generate(algorithm)

        val (ciphertext, iv) = wrappingKeyStore.encrypt(generated.privateKeyBytes)
        prefs().edit {
            putString(
                publicKeyPrefKey(alias),
                Base64.encodeToString(generated.publicKeyBytes, Base64.NO_WRAP)
            )
                .putString(
                    privateKeyPrefKey(alias),
                    Base64.encodeToString(ciphertext, Base64.NO_WRAP)
                )
                .putString(ivPrefKey(alias), Base64.encodeToString(iv, Base64.NO_WRAP))
        }

        return Base64.encodeToString(generated.publicKeyBytes, Base64.NO_WRAP)
    }

    fun clearAll() {
        prefs().edit { clear() }
        wrappingKeyStore.deleteKey()
    }

    private fun prefs(): SharedPreferences =
        context.getSharedPreferences("crypto_keys", Context.MODE_PRIVATE)

    private fun publicKeyPrefKey(alias: String): String = "pub:$alias"

    private fun privateKeyPrefKey(alias: String): String = "priv:$alias"

    private fun ivPrefKey(alias: String): String = "iv:$alias"
}

private class KeystoreAesGcm(
    private val alias: String,
    private val provider: String,
) {

    fun encrypt(plaintext: ByteArray): Pair<ByteArray, ByteArray> {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        return cipher.doFinal(plaintext) to cipher.iv
    }

    fun decrypt(ciphertext: ByteArray, iv: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(128, iv))
        return cipher.doFinal(ciphertext)
    }

    fun deleteKey() {
        val keyStore = KeyStore.getInstance(provider).apply { load(null) }
        if (keyStore.containsAlias(alias)) {
            keyStore.deleteEntry(alias)
        }
    }

    private fun getOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance(provider).apply { load(null) }
        val existing = keyStore.getKey(alias, null) as? SecretKey
        if (existing != null) return existing

        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, provider)
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()

        keyGenerator.init(spec)
        return keyGenerator.generateKey()
    }
}
