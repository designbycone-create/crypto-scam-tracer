package org.scamhunter.desk

import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

/** Sends one encrypted request to your Worker and opens the Desk's encrypted answer. */
class RelayClient(private val p: Pairing) {

    sealed class Outcome {
        class Ok(val r: RelayCrypto.Response) : Outcome()
        /** kind: offline, unpaired, slow, timeout, desk, network, crypto, error */
        class Fail(val kind: String, val detail: String) : Outcome()
    }

    fun call(method: String, path: String, body: ByteArray = ByteArray(0), ctype: String = ""): Outcome {
        val (rid, blob) = RelayCrypto.request(p.key, p.channel, method, path, body, ctype)
        var conn: HttpURLConnection? = null
        return try {
            conn = URL(p.worker + "/c/" + p.channel + "/req").openConnection() as HttpURLConnection
            conn.requestMethod = "POST"
            conn.doOutput = true
            conn.connectTimeout = 15000
            conn.readTimeout = 60000
            conn.instanceFollowRedirects = false
            conn.useCaches = false
            conn.setRequestProperty("Authorization", "Bearer " + p.token)
            conn.setRequestProperty("Content-Type", "application/octet-stream")
            conn.setFixedLengthStreamingMode(blob.size)
            conn.outputStream.use { it.write(blob) }
            val code = conn.responseCode
            if (code == 200) {
                val bytes = conn.inputStream.use { it.readBytes() }
                Outcome.Ok(RelayCrypto.response(p.key, p.channel, rid, bytes))
            } else {
                val msg = try {
                    JSONObject(String(conn.errorStream?.use { it.readBytes() } ?: ByteArray(0))).optString("error")
                } catch (e: Exception) { "" }
                val kind = when (code) {
                    503 -> "offline"; 401, 404 -> "unpaired"; 429 -> "slow"; 504 -> "timeout"; 502 -> "desk"; else -> "error"
                }
                Outcome.Fail(kind, if (msg.isNotBlank()) msg else "HTTP $code")
            }
        } catch (e: RelayException) {
            Outcome.Fail("crypto", e.message ?: "")
        } catch (e: IOException) {
            Outcome.Fail("network", e.message ?: "")
        } finally {
            conn?.disconnect()
        }
    }
}
