package com.novara.agent.util

import android.util.Base64
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.NamedParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.security.spec.XECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject

/**
 * On-device gate for .nova payloads. A packed file is useless here unless
 * three conditions all hold:
 *   1. The Ed25519 signature verifies against the embedded NOVA public key
 *      (only Novara can issue a payload).
 *   2. The X25519 key agreement succeeds against this device's private key
 *      (only this device can derive the data key).
 *   3. The AES-256-GCM tag + header AAD verify (nothing has been altered).
 *
 * Layout mirrors agent/tools/nova_pack.py exactly — keep the two in sync.
 */
object NovaPayload {
    private const val MAGIC = "NOVA"
    private const val X25519_PUB_LEN = 32
    private const val SALT_LEN = 16
    private const val NONCE_LEN = 12
    private const val SIG_LEN = 64
    private val json = Json { ignoreUnknownKeys = true }

    data class Opened(val manifest: JsonObject, val artifact: ByteArray, val name: String)

    /** Read os/arch/name from the cleartext header only; no keys required. */
    fun peek(data: ByteArray): JsonObject? = runCatching {
        val (os, arch, name) = parseHeader(data)
        json.parseToJsonElement(
            """{"os":"${os}","arch":"${arch}","artifact":"${name}"}""",
        ).jsonObject
    }.getOrNull()

    /**
     * Verify NOVA signature (Ed25519) without decrypting. novaPubPem is the
     * SPKI PEM of the company key embedded at build time.
     */
    fun verifyNovaSignature(data: ByteArray, novaPubPem: String): Boolean = runCatching {
        val (header, aadTail, nonce, ct, sig) = split(data)
        val pub = loadEd25519(novaPubPem)
        val verifier = Signature.getInstance("Ed25519")
        verifier.initVerify(pub)
        verifier.update(header + aadTail)
        verifier.update(nonce)
        verifier.update(ct)
        verifier.verify(sig)
    }.getOrDefault(false)

    /** Full gate: signature + device-key unlock + GCM integrity. */
    fun open(data: ByteArray, novaPubPem: String, deviceX25519Key: PrivateKey): Opened? {
        if (!verifyNovaSignature(data, novaPubPem)) return null
        val (header, aadTail, nonce, ct, _) = split(data)
        val (os, arch, name, _) = parseHeader(header)
        val ephPub = aadTail.copyOfRange(0, X25519_PUB_LEN)
        val salt = aadTail.copyOfRange(X25519_PUB_LEN, X25519_PUB_LEN + SALT_LEN)
        val aad = header + aadTail

        val shared = keyAgreementX25519(deviceX25519Key, ephPub) ?: return null
        val dek = hkdfSha256(shared, salt, "nova/payload-v1", 32)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(dek, "AES"), GCMParameterSpec(128, nonce), aad)
        val clear = runCatching { cipher.doFinal(ct) }.getOrNull() ?: return null

        val manifestLen = clear.copyOfRange(0, 8).let { b ->
            (0 until 8).fold(0L) { acc, i -> (acc shl 8) or (b[i].toLong() and 0xFF) }
        }
        val manifestJson = clear.copyOfRange(8, 8 + manifestLen.toInt())
        val artifact = clear.copyOfRange(8 + manifestLen.toInt(), clear.size)
        val manifest = json.parseToJsonElement(String(manifestJson)).jsonObject

        val expected = manifest["sha256"]?.jsonPrimitive?.content
        if (expected != null && expected != sha256Hex(artifact)) return null
        return Opened(manifest, artifact, manifest["name"]?.jsonPrimitive?.content ?: name)
    }

    private fun parseHeader(header: ByteArray): Triple<String, String, String, Int> {
        val osLen = header[6].toInt()
        val archLen = header[7 + osLen].toInt()
        val nameLen = header[8 + osLen + archLen].toInt()
        val os = String(header.copyOfRange(7, 7 + osLen))
        val arch = String(header.copyOfRange(8 + osLen, 8 + osLen + archLen))
        val name = String(header.copyOfRange(9 + osLen + archLen, 9 + osLen + archLen + nameLen))
        return Triple(os, arch, name)
    }

    private fun split(data: ByteArray): HeaderPair {
        check(data.copyOfRange(0, 4).toString(Charsets.ISO_8859_1) == MAGIC) { "bad magic" }
        val osLen = data[6].toInt()
        val archLen = data[7 + osLen].toInt()
        val nameLen = data[8 + osLen + archLen].toInt()
        val headerLen = 9 + osLen + archLen + nameLen
        val bodyStart = headerLen + X25519_PUB_LEN + SALT_LEN
        val header = data.copyOfRange(0, headerLen)
        val aadTail = data.copyOfRange(headerLen, bodyStart)
        val nonce = data.copyOfRange(bodyStart, bodyStart + NONCE_LEN)
        val ct = data.copyOfRange(bodyStart + NONCE_LEN, data.size - SIG_LEN)
        val sig = data.copyOfRange(data.size - SIG_LEN, data.size)
        return HeaderPair(header, aadTail, nonce, ct, sig)
    }

    private data class HeaderPair(val header: ByteArray, val aadTail: ByteArray, val nonce: ByteArray, val ct: ByteArray, val sig: ByteArray)

    private fun loadEd25519(pem: String): PublicKey {
        val key = pem
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replace("\\s".toRegex(), "")
        val spec = X509EncodedKeySpec(Base64.decode(key, Base64.DEFAULT))
        return KeyFactory.getInstance("Ed25519").generatePublic(spec)
    }

    /**
 * X25519 ECDH via the platform JCE (Conscrypt on Android 9+). The device
 * private key is the caller's responsibility — Android Keystore in
 * production. Returns the 32-byte shared secret, or null where X25519 is
 * unavailable (the gate closes safely).
 */
private fun keyAgreementX25519(deviceKey: PrivateKey, pubRaw: ByteArray): ByteArray? = runCatching {
    val uByteOrder = BigInteger(1, pubRaw.reversedArray())
    val spec = XECPublicKeySpec(NamedParameterSpec("X25519"), uByteOrder)
    val peer = KeyFactory.getInstance("X25519").generatePublic(spec)
    val agreement = KeyAgreement.getInstance("X25519")
    agreement.init(deviceKey)
    agreement.doPhase(peer, true)
    agreement.generateSecret()
}.getOrNull()

    private fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: String, length: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(salt, "HmacSHA256"))
        val prk = mac.doFinal(ikm)
        val out = ByteArrayOutputStream()
        var t = ByteArray(0)
        var counter = 1
        while (out.size() < length) {
            val inner = Mac.getInstance("HmacSHA256")
            inner.init(SecretKeySpec(prk, "HmacSHA256"))
            inner.update(t)
            inner.update(info.toByteArray())
            inner.update(counter.toByte())
            t = inner.doFinal()
            out.write(t)
            counter++
        }
        return out.toByteArray().copyOf(length)
    }

    private fun sha256Hex(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        return digest.joinToString("") { "%02x".format(it) }
    }
}