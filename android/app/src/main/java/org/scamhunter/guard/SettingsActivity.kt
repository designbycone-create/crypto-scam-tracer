package org.scamhunter.guard

import android.app.Activity
import android.os.Bundle
import android.widget.ArrayAdapter
import android.widget.CheckBox
import android.widget.Spinner
import android.widget.Toast
import java.text.DateFormat
import java.util.Date

class SettingsActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val col = Ui.page(this, "Settings")

        col.addView(Ui.text(this, "Family contact", 24f, bold = true))
        col.addView(Ui.text(this, "After a scam call, the app can prepare a text to this person. You still press Send.", 17f))
        val name = Ui.input(this, "Their name").apply { setText(Prefs.familyName(this@SettingsActivity)) }
        val num = Ui.input(this, "Their phone number", phone = true).apply { setText(Prefs.familyNumber(this@SettingsActivity)) }
        col.addView(name); col.addView(num)

        col.addView(Ui.text(this, "My details for reports", 24f, bold = true))
        col.addView(Ui.text(this, "Your name and address, so the FCC complaint form opens already filled in. Stays on this phone.", 17f))
        col.addView(Ui.button(this, "Fill in my details") { startActivity(android.content.Intent(this, MyDetailsActivity::class.java)) })

        col.addView(Ui.text(this, "Family code word", 24f, bold = true))
        col.addView(Ui.text(this, "A word only your family knows. If a \"grandchild\" calls in trouble, ask for it. AI can copy a voice, not a secret.", 17f))
        val code = Ui.input(this, "Code word (stays on this phone)").apply { setText(Prefs.codeWord(this@SettingsActivity)) }
        col.addView(code)

        col.addView(Ui.text(this, "Your state", 24f, bold = true))
        val states = listOf("Choose your state") + RecordingLaw.STATES
        val spin = Spinner(this).apply {
            adapter = ArrayAdapter(this@SettingsActivity, android.R.layout.simple_spinner_dropdown_item, states)
            setSelection(states.indexOf(Prefs.state(this@SettingsActivity)).coerceAtLeast(0))
        }
        col.addView(spin)

        val silence = CheckBox(this).apply { text = "Ring silently for numbers reported many times"; textSize = 20f; isChecked = Prefs.silenceHighRisk(this@SettingsActivity) }
        val warnAll = CheckBox(this).apply { text = "Also warn me for numbers reported only once or twice"; textSize = 20f; isChecked = Prefs.warnUnknown(this@SettingsActivity) }
        col.addView(silence); col.addView(warnAll)

        col.addView(Ui.button(this, "Save", Ui.GREEN) {
            Prefs.save(this, name.text.toString().trim(), num.text.toString().trim(),
                if (spin.selectedItemPosition > 0) states[spin.selectedItemPosition] else "", code.text.toString().trim(),
                silence.isChecked, warnAll.isChecked)
            Toast.makeText(this, "Saved", Toast.LENGTH_SHORT).show()
            finish()
        })

        col.addView(Ui.text(this, "Reported-numbers list", 24f, bold = true))
        val meta = NumberList.meta(this)
        val status = Ui.text(this, if (meta.optInt("count", 0) > 0)
            "${meta.optInt("count")} numbers, FTC reports up to ${meta.optString("to")}, downloaded " +
                DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(Date(meta.optLong("updated")))
        else "Not downloaded yet. It updates by itself once a day on Wi-Fi.", 17f)
        col.addView(status)
        col.addView(Ui.button(this, "Update the list now") {
            status.text = "Downloading..."
            Thread {
                val msg = try { "Done: ${NumberList.download(this)} reported numbers." } catch (e: Exception) { "Couldn't download: ${e.message}" }
                runOnUiThread { status.text = msg }
            }.start()
        })
        col.addView(Ui.text(this, "Source: the FTC's Do Not Call reported calls data. Reports are from the public and not verified.", 15f))
    }
}
