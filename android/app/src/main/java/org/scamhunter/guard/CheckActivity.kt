package org.scamhunter.guard

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.widget.LinearLayout

/** Check a message (also reached by "Share" from any app) or a phone number. */
class CheckActivity : Activity() {
    private lateinit var results: LinearLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val number = intent.getStringExtra("mode") == "number"
        val col = Ui.page(this, if (number) "Has this number been reported?" else "Is this message a scam?")
        val box = Ui.input(this, if (number) "Phone number" else "Paste or share the message here", multiline = !number, phone = number)
        val shared = intent.takeIf { it.action == Intent.ACTION_SEND }?.getStringExtra(Intent.EXTRA_TEXT)
        if (shared != null) box.setText(shared)
        col.addView(box)
        results = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        col.addView(Ui.button(this, "Check it") { if (number) showNumber(box.text.toString()) else showMessage(box.text.toString()) })
        col.addView(results)
        if (shared != null) showMessage(shared)
    }

    private fun showMessage(text: String) {
        results.removeAllViews()
        if (text.isBlank()) return
        val mc = Ui.checker(this)
        val r = mc.check(text)
        results.addView(Ui.banner(this, r.verdict, "", r.level))
        if (r.findings.isNotEmpty()) {
            results.addView(Ui.text(this, "What we noticed", 24f, bold = true))
            r.findings.forEach { results.addView(Ui.text(this, "• " + it.why)) }
        }
        results.addView(Ui.text(this, "What to do", 24f, bold = true))
        mc.advice(r).forEach { results.addView(Ui.text(this, "• $it")) }
        if (r.level != "info") results.addView(Ui.button(this, "Report it") {
            startActivity(Intent(this, ReportActivity::class.java).putExtra("story", text))
        })
    }

    private fun showNumber(s: String) {
        results.removeAllViews()
        val n = NumberList.norm(s)
        if (n == null) { results.addView(Ui.banner(this, "That isn't a US phone number", "Enter 10 digits.", "caution")); return }
        val meta = NumberList.meta(this)
        if (meta.optInt("count", 0) == 0) {
            results.addView(Ui.banner(this, "List not downloaded yet", "Open Settings and tap \"Update the list now\".", "caution")); return
        }
        val r = NumberList.rate(NumberList.lookup(this, n), meta.optInt("days", 30))
        results.addView(Ui.banner(this, if (r.level == "none") "No reports found" else r.headline,
            listOfNotNull(r.subject?.let { "Most reported as: $it" }, if (r.robocall) "Usually a recorded message (robocall)." else null)
                .joinToString("\n"), r.level))
        results.addView(Ui.text(this, "Reports come from people who got these calls and aren't verified. Scammers also fake real " +
            "people's numbers. No reports doesn't mean a call is safe.", 17f))
    }
}
