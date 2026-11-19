package org.scamhunter.desk

import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.Base64

/** Proves the phone encrypts exactly like the Desk (relay/envelope.py), using fixed vectors the Desk produced. */
class RelayCryptoTest {
    private val v = JSONObject(javaClass.classLoader!!.getResource("relay_vectors.json")!!.readText())
    private val key = Base64.getDecoder().decode(v.getString("key"))
    private val ch = v.getString("channel")
    private fun b64(s: String) = Base64.getDecoder().decode(s)

    private fun fails(block: () -> Unit) {
        try { block(); fail("should have been refused") } catch (e: RelayException) {}
    }

    @Test fun requestBytesIdenticalToTheDesk() {
        val r = v.getJSONObject("request")
        val mine = RelayCrypto.seal(key, ch, "req", r.getString("plaintext").toByteArray(), "", b64(r.getString("nonce")))
        assertArrayEquals(b64(r.getString("blob")), mine)
    }

    @Test fun opensTheDesksResponse() {
        val r = v.getJSONObject("response")
        val rid = r.getString("rid")
        val res = RelayCrypto.response(key, ch, rid, b64(r.getString("blob")))
        assertEquals(200, res.status)
        assertEquals("text/html; charset=utf-8", res.ctype)
        assertEquals(r.getString("page"), String(res.body, Charsets.UTF_8))
    }

    @Test fun responseForAnotherRequestRefused() {
        val r = v.getJSONObject("response")
        fails { RelayCrypto.response(key, ch, "ffffffffffffffffffffffff", b64(r.getString("blob"))) }
    }

    @Test fun tamperedOrWrongKeyOrChannelRefused() {
        val r = v.getJSONObject("response")
        val blob = b64(r.getString("blob"))
        val bad = blob.copyOf().also { it[30] = (it[30].toInt() xor 1).toByte() }
        fails { RelayCrypto.unseal(key, ch, "res", bad, r.getString("rid")) }
        fails { RelayCrypto.unseal(ByteArray(32), ch, "res", blob, r.getString("rid")) }
        fails { RelayCrypto.unseal(key, "f".repeat(32), "res", blob, r.getString("rid")) }
        fails { RelayCrypto.unseal(key, ch, "req", blob, r.getString("rid")) }
        fails { RelayCrypto.unseal(key, ch, "res", byteArrayOf(2, 3, 4), "") }
    }

    @Test fun requestRoundTripAndCompression() {
        val body = "text=".toByteArray() + "hello scam ".repeat(500).toByteArray()
        val (rid, blob) = RelayCrypto.request(key, ch, "POST", "/msgcheck", body, "application/x-www-form-urlencoded", 1795000000)
        val o = JSONObject(String(RelayCrypto.unseal(key, ch, "req", blob)))
        assertEquals(rid, o.getString("id"))
        assertEquals("/msgcheck", o.getString("p"))
        assertEquals(1, o.getInt("z"))
        assertArrayEquals(body, RelayCrypto.unpackBody(o.getString("b"), 1))
        assertEquals(24, rid.length)
    }

    @Test fun decompressionBombRefused() {
        val (b, z) = RelayCrypto.packBody(ByteArray(3 * 1024 * 1024))
        assertEquals(1, z)
        fails { RelayCrypto.unpackBody(b, z, 1024 * 1024) }
    }

    @Test fun pairingCodes() {
        val good = "shtd1:" + Base64.getUrlEncoder().withoutPadding().encodeToString(
            JSONObject().put("u", "https://scamhunter-relay.matt.workers.dev").put("c", "0123456789abcdef0123456789abcdef")
                .put("t", "x".repeat(43)).put("k", Base64.getEncoder().encodeToString(ByteArray(32))).toString().toByteArray())
        val p = Pairing.parse(good)
        assertNotNull(p)
        assertEquals("https://scamhunter-relay.matt.workers.dev", p!!.worker)
        assertEquals(32, Pairing.fromJson(p.toJson())!!.key.size)
        for (bad in listOf("", "hello", "shtd1:!!!", good.replace("https://", "http://"))) assertNull(bad, Pairing.parse(bad))
        val shortKey = "shtd1:" + Base64.getUrlEncoder().encodeToString(JSONObject().put("u", "https://a.b").put("c", "0".repeat(32))
            .put("t", "x".repeat(43)).put("k", Base64.getEncoder().encodeToString(ByteArray(16))).toString().toByteArray())
        assertNull(Pairing.parse(shortKey))
    }

    @Test fun formPostsCarriedThrough() {
        val body = "do=maigret&target=amy+lee"
        val enc = java.net.URLEncoder.encode(Base64.getEncoder().encodeToString(body.toByteArray()), "UTF-8")
        val (path, b) = Html.splitPost("/lookup?show=abc&__shpost=$enc")
        assertEquals("/lookup?show=abc", path)
        assertEquals(body, String(b!!))
        assertEquals(Pair("/case", null as ByteArray?).first, Html.splitPost("/case").first)
        assertNull(Html.splitPost("/case?x=1").second)
    }

    @Test fun redirectsStayOnTheDesk() {
        assertTrue(String(Html.redirect("/case")).contains("\"/case\""))
        assertTrue(String(Html.redirect("https://evil.example/")).contains("\"/\""))
        assertTrue(String(Html.redirect("//evil.example/")).contains("\"/\""))
        assertTrue(String(Html.redirect("/x\");alert(1);//")).contains("\"/\""))
    }

    @Test fun scriptAddedToPages() {
        val out = String(Html.inject("<html><body><p>hi</p></body></html>".toByteArray()))
        assertTrue(out.indexOf("__shtd") < out.indexOf("</body>"))
        assertTrue(String(Html.problem("offline", "<b>x</b>")).contains("&lt;b&gt;x&lt;/b&gt;"))
    }
}
