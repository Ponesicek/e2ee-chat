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

    suspend fun getIdentityPrivateKey(): ByteArray = withContext(Dispatchers.IO) {
        prefsStore.getPrivateKeyBytes(KeyAliases.IDENTITY)
    }

    suspend fun performX3DHHandshake(
        theirIdentityKey: String,
        theirSignedPreKey: String,
        theirSignedPreKeySignature: String,
        theirOneTimePreKey: String?,
    ): Result<X3DHResult> = withContext(Dispatchers.IO) {
        val myIdentityPrivateKey = getIdentityPrivateKey()
        X3DHHandshake.initiateFromContact(
            myIdentityPrivateKey = myIdentityPrivateKey,
            theirIdentityPublicKey = theirIdentityKey,
            theirSignedPreKey = theirSignedPreKey,
            theirSignedPreKeySignature = theirSignedPreKeySignature,
            theirOneTimePreKey = theirOneTimePreKey,
        ).map { it.getResult() }
    }

    suspend fun storeSession(contactId: String, sharedSecret: ByteArray, ephemeralPublicKey: String) = withContext(Dispatchers.IO) {
        val (encryptedSecret, iv) = prefsStore.encryptData(sharedSecret)
        prefsStore.storeSession(contactId, encryptedSecret, iv, ephemeralPublicKey)
    }

    suspend fun getSession(contactId: String): X3DHResult? = withContext(Dispatchers.IO) {
        prefsStore.getSession(contactId)
    }

    suspend fun hasSession(contactId: String): Boolean = withContext(Dispatchers.IO) {
        prefsStore.hasSession(contactId)
    }

    suspend fun respondToX3DH(
        theirIdentityKey: String,
        theirEphemeralKey: String,
        usedOneTimePreKeyId: String?,
    ): Result<X3DHResult> = withContext(Dispatchers.IO) {
        val mySignedPreKeyPrivate = prefsStore.getPrivateKeyBytes(KeyAliases.SIGNED_PREKEY)
        val myIdentityPrivateKey = getIdentityPrivateKey()
        val myOneTimePreKeyPrivate = usedOneTimePreKeyId?.toIntOrNull()?.let { index ->
            try {
                prefsStore.getPrivateKeyBytes(KeyAliases.oneTimePreKey(index))
            } catch (e: Exception) {
                null
            }
        }

        X3DHHandshake.respond(
            myIdentityPrivateKey = myIdentityPrivateKey,
            mySignedPreKeyPrivate = mySignedPreKeyPrivate,
            myOneTimePreKeyPrivate = myOneTimePreKeyPrivate,
            theirIdentityPublicKey = theirIdentityKey,
            theirEphemeralPublicKey = theirEphemeralKey,
        )
    }

    suspend fun getSignedPreKeyPublic(): String? = withContext(Dispatchers.IO) {
        prefsStore.getPublicKey(KeyAliases.SIGNED_PREKEY)
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
        sessionPrefs().edit { clear() }
        wrappingKeyStore.deleteKey()
    }

    fun encryptData(data: ByteArray): Pair<ByteArray, ByteArray> {
        return wrappingKeyStore.encrypt(data)
    }

    fun storeSession(contactId: String, encryptedSecret: ByteArray, iv: ByteArray, ephemeralPublicKey: String) {
        sessionPrefs().edit {
            putString(sessionSecretKey(contactId), Base64.encodeToString(encryptedSecret, Base64.NO_WRAP))
            putString(sessionIvKey(contactId), Base64.encodeToString(iv, Base64.NO_WRAP))
            putString(sessionEphemeralKey(contactId), ephemeralPublicKey)
        }
    }

    fun getSession(contactId: String): X3DHResult? {
        val encryptedSecretBase64 = sessionPrefs().getString(sessionSecretKey(contactId), null) ?: return null
        val ivBase64 = sessionPrefs().getString(sessionIvKey(contactId), null) ?: return null
        val ephemeralPublicKey = sessionPrefs().getString(sessionEphemeralKey(contactId), null) ?: return null

        val sharedSecret = wrappingKeyStore.decrypt(
            ciphertext = Base64.decode(encryptedSecretBase64, Base64.NO_WRAP),
            iv = Base64.decode(ivBase64, Base64.NO_WRAP),
        )
        return X3DHResult(sharedSecret, ephemeralPublicKey)
    }

    fun hasSession(contactId: String): Boolean {
        return sessionPrefs().contains(sessionSecretKey(contactId))
    }

    private fun prefs(): SharedPreferences =
        context.getSharedPreferences("crypto_keys", Context.MODE_PRIVATE)

    private fun sessionPrefs(): SharedPreferences =
        context.getSharedPreferences("crypto_sessions", Context.MODE_PRIVATE)

    private fun publicKeyPrefKey(alias: String): String = "pub:$alias"

    private fun privateKeyPrefKey(alias: String): String = "priv:$alias"

    private fun ivPrefKey(alias: String): String = "iv:$alias"

    private fun sessionSecretKey(contactId: String): String = "session_secret:$contactId"

    private fun sessionIvKey(contactId: String): String = "session_iv:$contactId"

    private fun sessionEphemeralKey(contactId: String): String = "session_ephemeral:$contactId"
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

data class X3DHResult(
    val sharedSecret: ByteArray,
    val ephemeralPublicKey: String,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is X3DHResult) return false
        return sharedSecret.contentEquals(other.sharedSecret) && ephemeralPublicKey == other.ephemeralPublicKey
    }

    override fun hashCode(): Int = 31 * sharedSecret.contentHashCode() + ephemeralPublicKey.hashCode()
}

sealed class X3DHError : Exception() {
    data object InvalidSignature : X3DHError()
    data object MissingKeys : X3DHError()
}

class X3DHHandshake private constructor(
    private val sharedSecret: ByteArray,
    private val ephemeralPublicKey: String,
) {

    fun getResult(): X3DHResult = X3DHResult(sharedSecret, ephemeralPublicKey)

    companion object Factory {
        private const val HKDF_INFO = "X3DH"
        private const val SHARED_SECRET_LENGTH = 32

        fun initiate(
            myIdentityPrivateKey: ByteArray,
            theirIdentityPublicKey: ByteArray,
            theirSignedPreKey: ByteArray,
            theirSignedPreKeySignature: ByteArray,
            theirOneTimePreKey: ByteArray?,
        ): Result<X3DHHandshake> {
            if (!verifySignedPreKey(theirIdentityPublicKey, theirSignedPreKey, theirSignedPreKeySignature)) {
                return Result.failure(X3DHError.InvalidSignature)
            }

            val ephemeralKeyPair = generateEphemeralKeyPair()
            val ephemeralPrivateKey = ephemeralKeyPair.privateKeyBytes
            val ephemeralPublicKey = ephemeralKeyPair.publicKeyBytes

            val myIdentityKeyX25519 = convertEd25519PrivateToX25519(myIdentityPrivateKey)

            val dh1 = x25519Agreement(myIdentityKeyX25519, theirSignedPreKey)
            val theirIdentityKeyX25519 = convertEd25519PublicToX25519(theirIdentityPublicKey)
            val dh2 = x25519Agreement(ephemeralPrivateKey, theirIdentityKeyX25519)
            val dh3 = if (theirOneTimePreKey != null) {
                x25519Agreement(ephemeralPrivateKey, theirOneTimePreKey)
            } else {
                ByteArray(0)
            }

//            android.util.Log.d("X3DH-INITIATE", "DH1: ${Base64.encodeToString(dh1, Base64.NO_WRAP)}")
//            android.util.Log.d("X3DH-INITIATE", "DH2: ${Base64.encodeToString(dh2, Base64.NO_WRAP)}")
//            android.util.Log.d("X3DH-INITIATE", "DH3: ${Base64.encodeToString(dh3, Base64.NO_WRAP)}")
//            android.util.Log.d("X3DH-INITIATE", "OTP used: ${theirOneTimePreKey != null}")

            val concatenatedSecrets = dh1 + dh2 + dh3
            val sharedSecret = hkdf(concatenatedSecrets, SHARED_SECRET_LENGTH)

            val ephemeralPublicKeyBase64 = Base64.encodeToString(ephemeralPublicKey, Base64.NO_WRAP)

            return Result.success(X3DHHandshake(sharedSecret, ephemeralPublicKeyBase64))
        }

        fun initiateFromContact(
            myIdentityPrivateKey: ByteArray,
            theirIdentityPublicKey: String,
            theirSignedPreKey: String,
            theirSignedPreKeySignature: String,
            theirOneTimePreKey: String?,
        ): Result<X3DHHandshake> {
            return initiate(
                myIdentityPrivateKey = myIdentityPrivateKey,
                theirIdentityPublicKey = Base64.decode(theirIdentityPublicKey, Base64.NO_WRAP),
                theirSignedPreKey = Base64.decode(theirSignedPreKey, Base64.NO_WRAP),
                theirSignedPreKeySignature = Base64.decode(theirSignedPreKeySignature, Base64.NO_WRAP),
                theirOneTimePreKey = theirOneTimePreKey?.let { Base64.decode(it, Base64.NO_WRAP) },
            )
        }

        fun respond(
            myIdentityPrivateKey: ByteArray,
            mySignedPreKeyPrivate: ByteArray,
            myOneTimePreKeyPrivate: ByteArray?,
            theirIdentityPublicKey: String,
            theirEphemeralPublicKey: String,
        ): Result<X3DHResult> {
            val theirIdentityBytes = Base64.decode(theirIdentityPublicKey, Base64.NO_WRAP)
            val theirEphemeralBytes = Base64.decode(theirEphemeralPublicKey, Base64.NO_WRAP)

            val myIdentityKeyX25519 = convertEd25519PrivateToX25519(myIdentityPrivateKey)
            val theirIdentityKeyX25519 = convertEd25519PublicToX25519(theirIdentityBytes)

            val dh1 = x25519Agreement(mySignedPreKeyPrivate, theirIdentityKeyX25519)
            val dh2 = x25519Agreement(myIdentityKeyX25519, theirEphemeralBytes)
            val dh3 = if (myOneTimePreKeyPrivate != null) {
                x25519Agreement(myOneTimePreKeyPrivate, theirEphemeralBytes)
            } else {
                ByteArray(0)
            }

            android.util.Log.d("X3DH-RESPOND", "DH1: ${Base64.encodeToString(dh1, Base64.NO_WRAP)}")
            android.util.Log.d("X3DH-RESPOND", "DH2: ${Base64.encodeToString(dh2, Base64.NO_WRAP)}")
            android.util.Log.d("X3DH-RESPOND", "DH3: ${Base64.encodeToString(dh3, Base64.NO_WRAP)}")
            android.util.Log.d("X3DH-RESPOND", "OTP used: ${myOneTimePreKeyPrivate != null}")

            val concatenatedSecrets = dh1 + dh2 + dh3
            val sharedSecret = hkdf(concatenatedSecrets, SHARED_SECRET_LENGTH)

            return Result.success(X3DHResult(sharedSecret, theirEphemeralPublicKey))
        }

        //OK
        private fun verifySignedPreKey(
            identityPublicKey: ByteArray,
            signedPreKey: ByteArray,
            signature: ByteArray,
        ): Boolean {
            return try {
                val verifier = Ed25519Signer().apply {
                    init(false, Ed25519PublicKeyParameters(identityPublicKey, 0))
                }
                verifier.update(signedPreKey, 0, signedPreKey.size)
                verifier.verifySignature(signature)
            } catch (e: Exception) {
                false
            }
        }

        //OK
        private fun generateEphemeralKeyPair(): GeneratedKeyPair {
            val keyGen = X25519KeyPairGenerator().apply {
                init(X25519KeyGenerationParameters(SecureRandom()))
            }
            val keyPair = keyGen.generateKeyPair()
            val privateKey = keyPair.private as X25519PrivateKeyParameters
            val publicKey = keyPair.public as X25519PublicKeyParameters
            return GeneratedKeyPair(publicKey.encoded, privateKey.encoded)
        }

        //OK
        private fun x25519Agreement(privateKey: ByteArray, publicKey: ByteArray): ByteArray {
            val privateKeyParams = X25519PrivateKeyParameters(privateKey, 0)
            val publicKeyParams = X25519PublicKeyParameters(publicKey, 0)
            val sharedSecret = ByteArray(32)
            privateKeyParams.generateSecret(publicKeyParams, sharedSecret, 0)
            return sharedSecret
        }

        //OK
        private fun convertEd25519PrivateToX25519(ed25519Private: ByteArray): ByteArray {
            val ed25519Params = Ed25519PrivateKeyParameters(ed25519Private, 0)
            val hash = org.bouncycastle.crypto.digests.SHA512Digest()
            val h = ByteArray(64)
            hash.update(ed25519Params.encoded, 0, 32)
            hash.doFinal(h, 0)

            h[0] = (h[0].toInt() and 248).toByte()
            h[31] = (h[31].toInt() and 127).toByte()
            h[31] = (h[31].toInt() or 64).toByte()

            return h.copyOf(32)
        }

        private fun convertEd25519PublicToX25519(ed25519Public: ByteArray): ByteArray {
            val pubBytes = ed25519Public.copyOf()
            pubBytes[31] = (pubBytes[31].toInt() and 0x7F).toByte() // Clear sign bit
            val y = java.math.BigInteger(1, pubBytes.reversedArray())
            val one = java.math.BigInteger.ONE
            val p = java.math.BigInteger("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16)

            val numerator = one.add(y).mod(p)
            val denominator = one.subtract(y).mod(p)
            val u = numerator.multiply(denominator.modInverse(p)).mod(p)

            val uBytes = u.toByteArray()
            val result = ByteArray(32)
            val sourceLen = minOf(uBytes.size, 32)
            val sourceStart = if (uBytes.size > 32) uBytes.size - 32 else 0
            val destStart = 32 - sourceLen

            for (i in 0 until sourceLen) {
                result[31 - destStart - i] = uBytes[sourceStart + i]
            }

            return result
        }

        private fun hkdf(inputKeyMaterial: ByteArray, length: Int): ByteArray {
            val salt = ByteArray(32)
            val hkdf = org.bouncycastle.crypto.generators.HKDFBytesGenerator(
                org.bouncycastle.crypto.digests.SHA256Digest()
            )
            hkdf.init(
                org.bouncycastle.crypto.params.HKDFParameters(
                    inputKeyMaterial,
                    salt,
                    HKDF_INFO.toByteArray()
                )
            )
            val output = ByteArray(length)
            hkdf.generateBytes(output, 0, length)
            return output
        }
    }
}