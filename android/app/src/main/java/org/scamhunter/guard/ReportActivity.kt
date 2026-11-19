package org.scamhunter.guard

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.speech.RecognizerIntent
import android.widget.CheckBox
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.RadioGroup
import android.widget.Toast
import java.text.DateFormat
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * After a scam call: the person tells the app what the caller said (by voice or typing). Their own
 * account of the call -- no call audio is ever recorded by the app. The checker reads it, then the
 * app prepares the report. The big button opens the FCC's complaint form already filled in (FccLink); the
 * FTC, Do Not Call and FBI (IC3) sites can't be pre-filled, so for those the report is copied to paste.
 * Nothing is sent until the person presses Send / Submit themselves.
 */
class ReportActivity : Activity() {
    private lateinit var number: android.widget.EditText
    private lateinit var story: android.widget.EditText
    private lateinit var lost: CheckBox
    private lateinit var kind: RadioGroup
    private lateinit var out: LinearLayout

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val col = Ui.page(this, "Report a call")
        col.addView(Ui.text(this, "Who called?", 22f, bold = true))
        number = Ui.input(this, "Their phone number", phone = true)
        number.setText(intent.getStringExtra("number") ?: Prefs.lastNumber(this))
        col.addView(number)
        col.addView(Ui.text(this, "What did they say or ask for?", 22f, bold = true))
        story = Ui.input(this, "For example: said he was from Medicare and asked for the code texted to me", multiline = true)
        intent.getStringExtra("story")?.let { story.setText(it) }
        col.addView(story)
        col.addView(Ui.button(this, "🎤  Say it instead of typing") { listen() })
        col.addView(Ui.text(this, "Was it...", 22f, bold = true))
        kind = RadioGroup(this)
        listOf("A recorded voice" to 1, "A real person" to 2, "A text message" to 3).forEach { (label, id) ->
            kind.addView(RadioButton(this).apply { text = label; textSize = 21f; this.id = id; minHeight = Ui.dp(this@ReportActivity, 52) })
        }
        col.addView(kind)
        lost = CheckBox(this).apply { text = "I lost money or gave out personal or bank details"; textSize = 21f }
        col.addView(lost)
        col.addView(Ui.button(this, "Check it and prepare my report", Ui.RED) { prepare() })
        out = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        col.addView(out)
    }

    private fun listen() {
        val i = Intent(RecognizerIntent.ACTION_RECOGNIZE_SPEECH)
            .putExtra(RecognizerIntent.EXTRA_LANGUAGE_MODEL, RecognizerIntent.LANGUAGE_MODEL_FREE_FORM)
            .putExtra(RecognizerIntent.EXTRA_PREFER_OFFLINE, true)          // stays on the phone where supported
            .putExtra(RecognizerIntent.EXTRA_PROMPT, "Tell me what the caller said or asked for")
        try { startActivityForResult(i, 7) } catch (e: ActivityNotFoundException) {
            Toast.makeText(this, "Voice typing isn't available; please type it.", Toast.LENGTH_LONG).show()
        }
    }

    @Deprecated("Activity result API without AndroidX")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 7 && resultCode == RESULT_OK) {
            val said = data?.getStringArrayListExtra(RecognizerIntent.EXTRA_RESULTS)?.firstOrNull() ?: return
            story.setText(listOf(story.text.toString().trim(), said).filter { it.isNotBlank() }.joinToString(" "))
        }
    }

    private fun prepare() {
        out.removeAllViews()
        val num = NumberList.norm(number.text.toString())
        val text = story.text.toString().trim()
        val mc = Ui.checker(this)
        val r = mc.check(text)
        val listInfo = num?.let { NumberList.rate(NumberList.lookup(this, it), NumberList.meta(this).optInt("days", 30)) }
        out.addView(Ui.banner(this, r.verdict, r.findings.take(4).joinToString("\n") { "• ${it.why}" }, r.level))
        if (listInfo != null && listInfo.level != "none") out.addView(Ui.text(this, "This number: ${listInfo.headline}.", 20f, bold = true))

        val when_ = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date())
        val report = buildString {
            append("Unwanted / scam call report\n")
            append("Caller number: ${num ?: number.text}\n")
            append("Date: $when_\n")
            append("What happened: $text\n")
            if (r.findings.isNotEmpty()) append("Warning signs: ${r.findings.joinToString("; ") { it.rule.replace('_', ' ') }}\n")
            if (lost.isChecked) append("Money or personal information was lost.\n")
        }
        // the FCC form opens already filled in
        val me = Prefs.me(this)
        val fcc = FccLink.url(FccLink.Report(
            callerNumber = num, date = callDay(num), time = callTime(num), description = report,
            kind = when (kind.checkedRadioButtonId) { 1 -> FccLink.Kind.RECORDING; 2 -> FccLink.Kind.PERSON; 3 -> FccLink.Kind.TEXT; else -> null },
            me = me))
        out.addView(Ui.button(this, "Report this call to the FCC", Ui.GREEN) { copyOpen(report, fcc, filled = true) })
        out.addView(Ui.text(this, "The government form opens already filled in. Answer the few yes/no questions left, " +
            "tick the box at the bottom, then tap Submit. Nothing is sent until you tap Submit.", 19f))
        if (me.isEmpty()) {
            out.addView(Ui.text(this, "Tip: add your name and address once, and the form fills those in too.", 18f, bold = true))
            out.addView(Ui.button(this, "Add my details", small = true) { startActivity(Intent(this, MyDetailsActivity::class.java)) })
        }
        out.addView(Ui.text(this, "Also report it (optional). These sites can't be filled in for you: the button copies your " +
            "report, then press and hold in their form and choose Paste.", 17f))
        out.addView(Ui.button(this, "Also report to the FTC", small = true) { copyOpen(report, "https://reportfraud.ftc.gov/") })
        out.addView(Ui.button(this, "Also report to Do Not Call", small = true) { copyOpen(report, "https://www.donotcall.gov/report.html") })
        if (lost.isChecked) {
            out.addView(Ui.banner(this, "You lost money or details", "Call your bank or card company now, using the number on your card. " +
                "Then report it to the FBI. If it was crypto, the ScamHunter Threat Desk can trace it for free.", "stop"))
            out.addView(Ui.button(this, "Report to the FBI (IC3)", Ui.RED) { copyOpen(report, "https://www.ic3.gov/") })
        }
        val fam = Prefs.familyNumber(this)
        if (fam.isNotBlank()) {
            val name = Prefs.familyName(this).ifBlank { "my family contact" }
            val msg = "ScamHunter Guard: I got a ${if (r.level == "stop") "likely scam" else "suspicious"} call from ${num ?: "a caller"} " +
                "at $when_. They said: \"${text.take(200)}\". ${if (lost.isChecked) "I may have lost money or details. Please call me." else "I didn't pay anything."}"
            out.addView(Ui.button(this, "Text $name about it", Ui.GREEN) {
                startActivity(Intent(Intent.ACTION_SENDTO, Uri.parse("smsto:$fam")).putExtra("sms_body", msg))
            })
        } else {
            out.addView(Ui.text(this, "Tip: add a family contact in Settings, and the app can prepare a text to them.", 17f))
        }
    }

    /** The time of the screened call if this is that number (within a day), otherwise now. */
    private fun callDate(num: String?): Date {
        val t = Prefs.lastTime(this)
        val same = num != null && NumberList.norm(Prefs.lastNumber(this)) == num
        return if (same && t > 0 && System.currentTimeMillis() - t < 24 * 3600_000L) Date(t) else Date()
    }
    private fun callDay(num: String?) = SimpleDateFormat("yyyy-MM-dd", Locale.US).format(callDate(num))
    private fun callTime(num: String?) = SimpleDateFormat("h:mm a", Locale.US).format(callDate(num))

    private fun copyOpen(text: String, url: String, filled: Boolean = false) {
        getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText("Scam call report", text))
        Toast.makeText(this, if (filled) "Opening the form, already filled in." else "Report copied. Paste it into the form.",
            Toast.LENGTH_LONG).show()
        try { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) } catch (e: ActivityNotFoundException) {
            Toast.makeText(this, "No web browser found on this phone.", Toast.LENGTH_LONG).show()
        }
    }
}
