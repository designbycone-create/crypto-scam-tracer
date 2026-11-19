package org.scamhunter.guard

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.URI
import java.net.URLDecoder

class FccLinkTest {
    private fun query(url: String): Map<String, String> {
        val u = URI(url)
        assertEquals("consumercomplaints.fcc.gov", u.host)
        assertEquals("https", u.scheme)
        return u.rawQuery.split("&").associate {
            val (k, v) = it.split("=", limit = 2)
            k to URLDecoder.decode(v, "UTF-8")
        }
    }

    private val me = FccLink.Me("Mary", "Smith", "12 Oak St", "Brewton", "Alabama", "36426", "(251) 555-0100", "mary@example.com")

    @Test fun fillsTheUnwantedCallForm() {
        val q = query(FccLink.url(FccLink.Report("2025550199", "2026-11-19", "10:30 AM",
            "Said he was from Medicare & asked for my code + card", FccLink.Kind.RECORDING, me)))
        assertEquals("39744", q["ticket_form_id"])
        assertEquals("Unwanted call from 2025550199", q["tf_subject"])
        assertEquals("Said he was from Medicare & asked for my code + card", q["tf_description"])   // & and + survive
        assertEquals("telemarketing_phone", q["tf_22619354"])
        assertEquals("phone_unwanted_calls_all_other_unwanted_calls", q["tf_360000167206"])
        assertEquals("prerecorded_voice_type_of_call_telemarketing", q["tf_22787840"])
        assertEquals("yes_caller_id_information", q["tf_22787920"])
        assertEquals("2025550199", q["tf_22659864"]); assertNull(q["tf_22664804"])   // hidden on this form: never filled
        assertEquals("2026-11-19", q["tf_22591154"]); assertEquals("10:30 AM", q["tf_22732340"])
        assertEquals("2515550100", q["tf_22625614"]); assertEquals("2515550100", q["tf_22615094"])
        assertEquals("Mary", q["tf_22539594"]); assertEquals("Smith", q["tf_22704720"])
        assertEquals("alabama", q["tf_22540114"]); assertEquals("36426", q["tf_22540124"])
        assertEquals("mary@example.com", q["tf_anonymous_requester_email"])
        assertEquals("no_filing_on_behalf", q["tf_22636844"])
    }

    /** Writes a sample link (test values only) so it can be opened against the live FCC form as an outside check. */
    @Test fun writeSampleLink() {
        val url = FccLink.url(FccLink.Report("2025550199", "2026-11-19", "10:30 AM",
            "TEST ONLY - do not submit. Said he was from Medicare & asked for my code + card", FccLink.Kind.RECORDING, me))
        val out = java.io.File("build/fcc-sample-link.txt"); out.parentFile?.mkdirs(); out.writeText(url)
        println("FCC_SAMPLE_LINK=$url")
    }

    @Test fun neverTicksTheAttestBox() {
        val url = FccLink.url(FccLink.Report("2025550199", "2026-11-19", "9:00 AM", "x", FccLink.Kind.PERSON, me))
        assertFalse(url.contains(FccLink.F_ATTEST))
    }

    @Test fun spacesAreNotPlusSigns() {
        val url = FccLink.url(FccLink.Report(null, "2026-11-19", "9:00 AM", "a b"))
        assertFalse(url.contains("+"))
        assertTrue(url.contains("a%20b"))
    }

    @Test fun unknownCallerAndNoDetailsLeaveThoseFieldsOut() {
        val q = query(FccLink.url(FccLink.Report(null, "2026-11-19", "9:00 AM", "Hung up", null)))
        assertEquals("Unwanted call", q["tf_subject"])
        assertNull(q["tf_22787920"]); assertNull(q["tf_22659864"]); assertNull(q["tf_22787840"])
        assertNull(q["tf_22539594"]); assertNull(q["tf_22636844"]); assertNull(q["tf_anonymous_requester_email"])
    }

    @Test fun anglesAreRemovedAndLongTextTrimmed() {
        val q = query(FccLink.url(FccLink.Report(null, "2026-11-19", "9:00 AM", "<script>" + "x".repeat(5000))))
        assertFalse(q["tf_description"]!!.contains('<')); assertFalse(q["tf_description"]!!.contains('>'))
        assertEquals(1500, q["tf_description"]!!.length)
    }

    @Test fun stateTagsMatchTheForm() {
        assertEquals("district_of_columbia", FccLink.stateTag("District of Columbia"))
        assertEquals("new_hampshire", FccLink.stateTag("New Hampshire"))
        RecordingLaw.STATES.forEach { assertTrue(it, FccLink.stateTag(it).matches(Regex("[a-z_]+"))) }
    }

    @Test fun phoneDigits() {
        assertEquals("2515550100", FccLink.digits("+1 (251) 555-0100"))
        assertEquals("2515550100", FccLink.digits("251.555.0100"))
    }
}
