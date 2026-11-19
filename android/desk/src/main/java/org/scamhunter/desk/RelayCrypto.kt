package org.scamhunter.desk

import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.util.Base64
import java.util.zip.Deflater
import java.util.zip.Inflater
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class RelayException(msg: String) : Exception(msg)

/**
 * End-to-end encryption with the Desk -- byte-for-byte the same as relay/envelope.py on the PC
 * (proven by the fixed vectors in src/test/resources/relay_vectors.json).
 *
 * blob = 0x01 | nonce (12 bytes) | AES-256-GCM ciphertext+tag
 * AAD  = "shtd1|<channel>|req|" for requests, "shtd1|<channel>|res|<request id>" for responses.
 */
object RelayCrypto {
    private const val VERSION: Byte = 1
    const val MAX_BODY = 4 * 1024 * 1024
    private val rnd = SecureRandom()

    fun aad(channel: String, dir: String, rid: String = "") = "shtd1|$channel|$dir|$rid".toByteArray(Charsets.UTF_8)

    fun seal(key: ByteArray, channel: String, dir: String, plaintext: ByteArray, rid: String = "", nonce: ByteArray? = null): ByteArray {
        val n = nonce ?: ByteArray(12).also { rnd.nextBytes(it) }
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, n))
        c.updateAAD(aad(channel, dir, rid))
        return byteArrayOf(VERSION) + n + c.doFinal(plaintext)
    }

    fun unseal(key: ByteArray, channel: String, dir: String, blob: ByteArray, rid: String = ""): ByteArray {
        if (blob.size < 1 + 12 + 16 || blob[0] != VERSION) throw RelayException("not a ScamHunter message")
        return try {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, blob.copyOfRange(1, 13)))
            c.updateAAD(aad(channel, dir, rid))
            c.doFinal(blob, 13, blob.size - 13)
        } catch (e: Exception) {
            throw RelayException("the answer failed its integrity check")
        }
    }

    /** bytes -> (base64, compressed 0/1); zlib format, same as Python's zlib.compress */
    fun packBody(data: ByteArray): Pair<String, Int> {
        val d = Deflater(6)
        d.setInput(data)
        d.finish()
        val out = ByteArrayOutputStream()
        val buf = ByteArray(8192)
        while (!d.finished()) out.write(buf, 0, d.deflate(buf))
        d.end()
        val z = out.toByteArray()
        return if (z.size < data.size) Pair(Base64.getEncoder().encodeToString(z), 1) else Pair(Base64.getEncoder().encodeToString(data), 0)
    }

    fun unpackBody(b64: String, z: Int, max: Int = MAX_BODY): ByteArray {
        val raw = Base64.getDecoder().decode(b64)
        if (z == 0) return raw
        val inf = Inflater()
        inf.setInput(raw)
        val out = ByteArrayOutputStream()
        val buf = ByteArray(16384)
        try {
            while (!inf.finished()) {
                val n = inf.inflate(buf)
                if (n == 0 && (inf.needsInput() || inf.needsDictionary())) break
                out.write(buf, 0, n)
                if (out.size() > max) throw RelayException("answer too large")
            }
        } finally {
            inf.end()
        }
        return out.toByteArray()
    }

    fun newId(): String = ByteArray(12).also { rnd.nextBytes(it) }.joinToString("") { "%02x".format(it) }

    /** Build an encrypted request. Returns (request id, blob). */
    fun request(key: ByteArray, channel: String, method: String, path: String, body: ByteArray, ctype: String,
                nowSec: Long = System.currentTimeMillis() / 1000): Pair<String, ByteArray> {
        val rid = newId()
        val (b, z) = packBody(body)
        val o = JSONObject()
        o.put("v", 1); o.put("id", rid); o.put("ts", nowSec); o.put("m", method); o.put("p", path); o.put("ct", ctype); o.put("b", b); o.put("z", z)
        return Pair(rid, seal(key, channel, "req", o.toString().toByteArray(Charsets.UTF_8)))
    }

    class Response(val status: Int, val ctype: String, val location: String, val body: ByteArray)

    fun response(key: ByteArray, channel: String, rid: String, blob: ByteArray): Response {
        val o = JSONObject(String(unseal(key, channel, "res", blob, rid), Charsets.UTF_8))
        if (o.optString("id") != rid) throw RelayException("answer to a different request")
        return Response(o.optInt("s", 502), o.optString("ct", "text/html; charset=utf-8"), o.optString("loc", ""),
            unpackBody(o.optString("b", ""), o.optInt("z", 0)))
    }
}
