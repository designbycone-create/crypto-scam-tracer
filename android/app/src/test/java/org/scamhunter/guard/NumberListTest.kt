package org.scamhunter.guard

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.nio.file.Files

class NumberListTest {
    // the same compact format the Desk's callerlist.export writes
    private val published = """{"v":1,"to":"2026-11-15","days":30,
        "s":["Imposters - Government","Reducing your debt","Warranties"],
        "n":{"8335551234":[37,30,0,1],"2025550199":[4,0,1,3],"9095550100":[1,1,2,10],"5551234":[9,9,0,0]}}"""

    @Test fun installAndLookUp() {
        val dir = Files.createTempDirectory("nl").toFile()
        assertEquals(3, NumberList.installIn(dir, published))            // the malformed 7-digit entry is dropped
        val h = NumberList.lookupIn(dir, "+1 (833) 555-1234")!!
        assertEquals(37, h.reports); assertEquals("Imposters - Government", h.subject); assertEquals(1, h.daysAgo)
        assertEquals(4, NumberList.lookupIn(dir, "202-555-0199")!!.reports)
        assertEquals(1, NumberList.lookupIn(dir, "9095550100")!!.reports)
        assertNull(NumberList.lookupIn(dir, "3125550000"))
        assertNull(NumberList.lookupIn(dir, "12"))
    }

    @Test fun ratingsMatchTheDesk() {
        fun lv(n: Int, s: String) = NumberList.rate(NumberList.Hit("x", n, 0, s, 0), 30).level
        assertEquals("high", lv(37, "Imposters - Government"))
        assertEquals("high", lv(4, "Imposters - Government"))      // several reports + fraud subject
        assertEquals("medium", lv(4, "Home improvement"))
        assertEquals("low", lv(1, "Imposters - Government"))       // never high on one report
        assertEquals("none", NumberList.rate(null, 30).level)
    }

    @Test fun phoneNumberFormats() {
        assertEquals("8335551234", NumberList.norm("+1 833-555-1234"))
        assertNull(NumberList.norm("0335551234"))
        assertNull(NumberList.norm("555-1234"))
    }
}
