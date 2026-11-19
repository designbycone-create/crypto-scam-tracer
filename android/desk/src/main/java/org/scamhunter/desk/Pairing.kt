package org.scamhunter.desk

import org.json.JSONObject
import java.util.Base64

/** What the Desk's pairing QR code holds: your Worker, the channel, this phone's token and the encryption key. */
class Pairing(val worker: String, val channel: String, val token: String, val key: ByteArray) {

    fun toJson(): String = JSONObject().put("u", worker).put("c", channel).put("t", token)
        .put("k", Base64.getEncoder().encodeToString(key)).toString()

    companion object {
        private val WORKER = Regex("https://[a-z0-9]([a-z0-9-]*[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+")
        private val CHANNEL = Regex("[0-9a-f]{32}")

        /** Parse "shtd1:..." from the QR code (or pasted), or null if it isn't a valid pairing code. */
        fun parse(code: String): Pairing? {
            val c = code.trim()
            if (!c.startsWith("shtd1:")) return null
            return try {
                fromJson(String(Base64.getUrlDecoder().decode(c.substring(6)), Charsets.UTF_8))
            } catch (e: Exception) {
                null
            }
        }

        fun fromJson(s: String): Pairing? = try {
            val o = JSONObject(s)
            val p = Pairing(o.getString("u").trimEnd('/'), o.getString("c"), o.getString("t"), Base64.getDecoder().decode(o.getString("k")))
            if (WORKER.matches(p.worker) && CHANNEL.matches(p.channel) && p.token.length >= 20 && p.key.size == 32) p else null
        } catch (e: Exception) {
            null
        }
    }
}
