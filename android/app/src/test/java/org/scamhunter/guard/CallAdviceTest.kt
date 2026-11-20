package org.scamhunter.guard

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class CallAdviceTest {
    private fun r(reports: Int, subject: String = "Warranties") =
        NumberList.rate(if (reports == 0) null else NumberList.Hit("2025550199", reports, 0, subject, 1), 30)

    @Test fun reportedManyTimesIsAStop() {
        val a = CallAdvice.advise(r(37, "Imposters - Government"), warnLow = false, warnNotContact = false)!!
        assertEquals("stop", a.level); assertEquals("LIKELY SCAM CALL", a.title)
        assertTrue(a.body.contains("Imposters - Government")); assertTrue(a.body.contains("gift cards"))
    }

    @Test fun aFewReportsIsCaution() =
        assertEquals("caution", CallAdvice.advise(r(4), false, false)!!.level)

    @Test fun unreportedUnknownNumberGetsTheCalmCardByDefault() {
        val a = CallAdvice.advise(r(0), warnLow = false, warnNotContact = true)!!
        assertEquals("unknown", a.level); assertEquals("Unknown caller", a.title)
    }

    @Test fun onceOrTwiceReportedFollowsTheSettings() {
        assertEquals("unknown", CallAdvice.advise(r(1), warnLow = false, warnNotContact = true)!!.level)
        assertEquals("caution", CallAdvice.advise(r(1), warnLow = true, warnNotContact = true)!!.level)
        assertNull(CallAdvice.advise(r(1), warnLow = false, warnNotContact = false))
    }

    @Test fun nothingWhenTheUnknownReminderIsOff() = assertNull(CallAdvice.advise(r(0), false, false))
}
