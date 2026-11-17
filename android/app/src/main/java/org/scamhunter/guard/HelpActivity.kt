package org.scamhunter.guard

import android.app.Activity
import android.content.Intent
import android.os.Bundle

/** The "Am I being scammed?" screen: one look, during a call, in big letters. No recording. */
class HelpActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val col = Ui.page(this, "It's OK to hang up.")
        col.addView(Ui.banner(this, "It IS a scam if they:", listOf(
            "ask for gift cards, a Bitcoin ATM, cash pickup or a wire",
            "ask for a code that was texted to you",
            "say to keep it secret, or not to hang up",
            "threaten arrest, or say your Social Security number is suspended",
            "say to move your money to a \"safe account\"",
            "want to get into your computer",
            "say a family member is in jail or hurt and needs money now",
        ).joinToString("\n") { "• $it" }, "stop"))
        col.addView(Ui.text(this, "Real banks, police and government offices never do these things.", 22f, bold = true))
        val code = Prefs.codeWord(this)
        col.addView(Ui.banner(this, "Family emergency call?",
            "Voices can be faked with AI. Hang up and call your family member on the number you already have." +
                if (code.isNotBlank()) "\nOr ask for your family code word." else "\nSet a family code word in Settings.", "caution"))
        col.addView(Ui.banner(this, "Bank or government call?",
            "Hang up. Call the number on the back of your card, or the agency's official number. Not a number the caller gave you.", "caution"))
        col.addView(Ui.text(this, RecordingLaw.note(Prefs.state(this)), 17f))
        col.addView(Ui.button(this, "After the call: report it") { startActivity(Intent(this, ReportActivity::class.java)) })
    }
}
