package org.scamhunter.desk

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** The pairing, kept sealed with a key in the phone's hardware-backed Android Keystore (it never leaves the phone). */
object Store {
    private const val PREFS = "desk"
    private const val ALIAS = "scamhunter_desk_pairing"

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val g = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        g.init(KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256).build())
        return g.generateKey()
    }

    private fun seal(plain: String): String {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, key())
        return Base64.getEncoder().encodeToString(c.iv + c.doFinal(plain.toByteArray(Charsets.UTF_8)))
    }

    private fun open(sealed: String): String? = try {
        val b = Base64.getDecoder().decode(sealed)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, b.copyOfRange(0, 12)))
        String(c.doFinal(b, 12, b.size - 12), Charsets.UTF_8)
    } catch (e: Exception) {
        null
    }

    fun pairing(c: Context): Pairing? {
        val s = c.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString("pairing", null) ?: return null
        return open(s)?.let { Pairing.fromJson(it) }
    }

    fun save(c: Context, p: Pairing) {
        c.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString("pairing", seal(p.toJson())).apply()
    }

    fun forget(c: Context) {
        c.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().remove("pairing").apply()
    }

    fun zoom(c: Context): Int = c.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getInt("zoom", 115)

    fun setZoom(c: Context, z: Int) {
        c.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putInt("zoom", z.coerceIn(80, 200)).apply()
    }
}
