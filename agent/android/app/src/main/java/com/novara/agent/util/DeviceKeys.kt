package com.novara.agent.util

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

/**
 * The device's long-term X25519 keypair. Kept in the hardware-backed
 * Android Keystore on Android 12+, with an internal-storage PKCS8 fallback
 * on older builds (0600, no backup). The public half is uploaded at
 * registration so NOVA can pack .nova payloads to exactly this device.
 */
object DeviceKeys {
    private const val ALIAS = "nova_device_x25519"
    private const val FALLBACK_PRIV = "novakey_priv.p8"
    private const val FALLBACK_PUB = "novakey_pub.p8"

    fun keyPair(context: Context): KeyPair = loadFromKeystore()
        ?: loadFromFile(context)
        ?: createNew(context)

    fun privateKey(context: Context): PrivateKey = keyPair(context).private

    private fun loadFromKeystore(): KeyPair? {
        return runCatching {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val priv = ks.getKey(ALIAS, null) as? PrivateKey ?: return null
            val pub = ks.getCertificate(ALIAS)?.publicKey ?: return null
            KeyPair(pub, priv)
        }.getOrNull()
    }

    private fun loadFromFile(context: Context): KeyPair? {
        val privFile = java.io.File(context.noBackupFilesDir, FALLBACK_PRIV)
        val pubFile = java.io.File(context.noBackupFilesDir, FALLBACK_PUB)
        if (!privFile.exists() || !pubFile.exists()) return null
        return runCatching {
            val fact = java.security.KeyFactory.getInstance("X25519")
            val priv = fact.generatePrivate(PKCS8EncodedKeySpec(privFile.readBytes()))
            val pub = fact.generatePublic(X509EncodedKeySpec(pubFile.readBytes()))
            KeyPair(pub, priv)
        }.getOrNull()
    }

    private fun createNew(context: Context): KeyPair {
        val keystorePair = runCatching {
            val kpg = KeyPairGenerator.getInstance("X25519", "AndroidKeyStore")
            kpg.initialize(
                KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_AGREE_KEY)
                    .build(),
            )
            kpg.generateKeyPair()
        }.getOrNull()
        keystorePair?.let { return it }

        val pair = KeyPairGenerator.getInstance("X25519").genKeyPair()
        val privFile = java.io.File(context.noBackupFilesDir, FALLBACK_PRIV)
        val pubFile = java.io.File(context.noBackupFilesDir, FALLBACK_PUB)
        privFile.writeBytes(pair.private.encoded)
        pubFile.writeBytes(pair.public.encoded)
        privFile.setReadable(false)
        privFile.setWritable(true, true)
        privFile.setExecutable(false)
        return pair
    }
}