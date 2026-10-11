package dev.phonetpm.app

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import org.json.JSONArray
import org.json.JSONObject
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import uniffi.phonetpm_mobile.KeyInfo
import uniffi.phonetpm_mobile.KeyKind

data class KeyMeta(
    val id: String,
    val label: String,
    val kind: KeyKind,
    val createdAt: Long,
    val strongBox: Boolean,
)

/**
 * Biometric-bound EC P-256 keys in Android Keystore. The Keystore alias is
 * the key id; label/kind/createdAt/strongBox live in SharedPreferences.
 */
class KeyStoreRepo(ctx: Context) {
    private val prefs = ctx.getSharedPreferences("keys", Context.MODE_PRIVATE)
    private val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    private val state = MutableStateFlow(load())
    val all: StateFlow<List<KeyMeta>> = state

    fun find(id: String): KeyMeta? = state.value.firstOrNull { it.id == id }

    /** SPKI DER of the key's public half, or null if the Keystore entry is gone. */
    fun publicKey(id: String): ByteArray? = keyStore.getCertificate(id)?.publicKey?.encoded

    fun privateKey(id: String): PrivateKey? = keyStore.getKey(id, null) as? PrivateKey

    /**
     * The ECDH peer key from [spki] if it is a P-256 SPKI with an uncompressed
     * point on the curve of key [id]; else null (also if the key is gone).
     */
    fun ecdhPeerKey(id: String, spki: ByteArray): ECPublicKey? {
        val params = (keyStore.getCertificate(id)?.publicKey as? ECPublicKey)?.params ?: return null
        return p256PeerKey(spki, params)
    }

    fun keyInfos(): List<KeyInfo> = state.value.mapNotNull { m ->
        publicKey(m.id)?.let { KeyInfo(m.id, m.label, m.kind, it) }
    }

    /** Blocking; StrongBox key generation can take a while. */
    @Synchronized
    fun create(label: String, kind: KeyKind): KeyMeta {
        val id = newId()
        val strongBox = generate(id, kind)
        val meta = KeyMeta(id, label, kind, System.currentTimeMillis(), strongBox)
        save(state.value + meta)
        return meta
    }

    @Synchronized
    fun delete(id: String) {
        if (keyStore.containsAlias(id)) keyStore.deleteEntry(id)
        save(state.value.filterNot { it.id == id })
    }

    /** Returns whether the key ended up in StrongBox. */
    private fun generate(alias: String, kind: KeyKind): Boolean {
        try {
            generate(alias, kind, strongBox = true)
            return true
        } catch (_: StrongBoxUnavailableException) {
            generate(alias, kind, strongBox = false)
            return false
        }
    }

    private fun generate(alias: String, kind: KeyKind, strongBox: Boolean) {
        val purposes = when (kind) {
            KeyKind.SSH -> KeyProperties.PURPOSE_SIGN
            KeyKind.AGE -> KeyProperties.PURPOSE_AGREE_KEY
        }
        val spec = KeyGenParameterSpec.Builder(alias, purposes)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
            .apply {
                when (kind) {
                    KeyKind.SSH -> {
                        setDigests(KeyProperties.DIGEST_SHA256)
                        // Per-operation auth via BiometricPrompt CryptoObject.
                        setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                    }
                    KeyKind.AGE -> {
                        // A KeyAgreement CryptoObject needs API 36 and
                        // androidx.biometric 1.4.0-alpha06+; with compileSdk 35
                        // and biometric 1.1.0, a short post-auth window is the
                        // tightest option.
                        setUserAuthenticationParameters(AGE_AUTH_WINDOW_SECONDS, KeyProperties.AUTH_BIOMETRIC_STRONG)
                    }
                }
                if (strongBox) setIsStrongBoxBacked(true)
            }
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE).run {
            initialize(spec)
            generateKeyPair()
        }
    }

    private fun save(keys: List<KeyMeta>) {
        val arr = JSONArray()
        for (k in keys) {
            arr.put(
                JSONObject()
                    .put("id", k.id)
                    .put("label", k.label)
                    .put("kind", k.kind.name)
                    .put("createdAt", k.createdAt)
                    .put("strongBox", k.strongBox)
            )
        }
        prefs.edit().putString(KEY, arr.toString()).apply()
        state.value = keys
    }

    private fun load(): List<KeyMeta> {
        val raw = prefs.getString(KEY, null) ?: return emptyList()
        val arr = JSONArray(raw)
        return List(arr.length()) { i ->
            val o = arr.getJSONObject(i)
            KeyMeta(
                id = o.getString("id"),
                label = o.getString("label"),
                kind = KeyKind.valueOf(o.getString("kind")),
                createdAt = o.getLong("createdAt"),
                strongBox = o.optBoolean("strongBox", false),
            )
        }
    }

    companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val AGE_AUTH_WINDOW_SECONDS = 10
        private const val KEY = "keys"
        private const val HEX = "0123456789abcdef"

        private fun newId(): String {
            val rnd = ByteArray(8).also { SecureRandom().nextBytes(it) }
            return buildString(16) {
                for (b in rnd) {
                    append(HEX[(b.toInt() shr 4) and 0xf])
                    append(HEX[b.toInt() and 0xf])
                }
            }
        }

        /** DER of a named-curve P-256 SPKI up to and including the uncompressed-point tag 0x04. */
        private val P256_SPKI_PREFIX = "3059301306072a8648ce3d020106082a8648ce3d03010703420004"
            .chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        private const val COORDINATE_BYTES = 32

        /**
         * Parses [spki] as `P256_SPKI_PREFIX || X || Y` and checks the point lies
         * on the curve of [params] (y² = x³ + ax + b mod p), so that no
         * invalid-curve point reaches the Keystore's ECDH.
         */
        fun p256PeerKey(spki: ByteArray, params: ECParameterSpec): ECPublicKey? {
            val n = P256_SPKI_PREFIX.size
            if (spki.size != n + 2 * COORDINATE_BYTES || !spki.copyOfRange(0, n).contentEquals(P256_SPKI_PREFIX)) {
                return null
            }
            val x = BigInteger(1, spki.copyOfRange(n, n + COORDINATE_BYTES))
            val y = BigInteger(1, spki.copyOfRange(n + COORDINATE_BYTES, spki.size))
            val curve = params.curve
            val p = (curve.field as? ECFieldFp)?.p ?: return null
            if (x >= p || y >= p) return null
            val rhs = x.pow(3).add(curve.a.multiply(x)).add(curve.b).mod(p)
            if (y.multiply(y).mod(p) != rhs) return null
            return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), params)) as ECPublicKey
        }

        /** OpenSSH-style `SHA256:<base64 without padding>` fingerprint of SPKI DER. */
        fun fingerprint(spki: ByteArray): String {
            val digest = MessageDigest.getInstance("SHA-256").digest(spki)
            return "SHA256:" + android.util.Base64.encodeToString(digest, android.util.Base64.NO_WRAP or android.util.Base64.NO_PADDING)
        }
    }
}
