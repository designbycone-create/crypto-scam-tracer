package org.scamhunter.guard

import org.json.JSONArray
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** The phone must reach the same verdicts as the ScamHunter Threat Desk on the shared sample (parity.json,
 *  produced by tools/export_mobile_rules.py from the Desk's own checker). */
class MsgCheckParityTest {
    private val mc = MsgCheck(File("src/main/assets/scam_rules.json").readText())

    @Test fun sameVerdictsAsTheDesk() {
        val cases = JSONArray(javaClass.classLoader!!.getResource("parity.json")!!.readText())
        val wrong = mutableListOf<String>()
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val r = mc.check(c.getString("text"))
            val want = (0 until c.getJSONArray("rules").length()).map { c.getJSONArray("rules").getString(it) }.toSortedSet()
            val got = r.findings.map { it.rule }.toSortedSet()
            if (r.verdict != c.getString("verdict") || got != want)
                wrong += "${c.getString("text").take(50)} -> phone ${r.verdict} $got, desk ${c.getString("verdict")} $want"
        }
        assertTrue(wrong.joinToString("\n"), wrong.isEmpty())
        assertTrue("sample too small", cases.length() >= 20)
    }

    @Test fun campaignAddressIsCaught() {
        val r = mc.check("Deposit here: THvs6p56XkUiMkJeSc51cAP64u2RsTYqxa")
        assertTrue(r.findings.any { it.rule == "bad_address" })
    }
}
