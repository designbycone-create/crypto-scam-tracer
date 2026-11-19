package org.scamhunter.guard

import android.app.Activity
import android.os.Bundle
import android.text.InputType
import android.widget.ArrayAdapter
import android.widget.Spinner
import android.widget.Toast

/**
 * Filled in once: the person's own name, address and contact, so the FCC complaint form opens already filled.
 * Stays on this phone only. The app never sends it anywhere; it goes into the form only when the person
 * taps "Report this call to the FCC", and nothing is submitted until they tap Submit on the FCC's site.
 */
class MyDetailsActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val col = Ui.page(this, "My details for reports")
        col.addView(Ui.text(this, "Fill this in once. Then, when you report a scam call, the government form opens already " +
            "filled in for you. It stays on this phone. You can skip any line.", 19f))
        val m = Prefs.me(this)
        fun field(label: String, value: String, type: Int = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_WORDS) =
            Ui.input(this, label).apply { inputType = type; setText(value) }.also {
                col.addView(Ui.text(this, label, 20f, bold = true)); col.addView(it)
            }
        val first = field("First name", m.first)
        val last = field("Last name", m.last)
        val addr = field("Street address", m.address)
        val city = field("City", m.city)
        col.addView(Ui.text(this, "State", 20f, bold = true))
        val states = listOf("Choose your state") + RecordingLaw.STATES
        val spin = Spinner(this).apply {
            adapter = ArrayAdapter(this@MyDetailsActivity, android.R.layout.simple_spinner_dropdown_item, states)
            setSelection(states.indexOf(m.state).coerceAtLeast(0))
        }
        col.addView(spin)
        val zip = field("ZIP code", m.zip, InputType.TYPE_CLASS_NUMBER)
        val phone = field("Your phone number (this phone)", m.phone, InputType.TYPE_CLASS_PHONE)
        val email = field("Your email (the FCC sends your complaint number here)", m.email,
            InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS)

        col.addView(Ui.button(this, "Save", Ui.GREEN) {
            Prefs.saveMe(this, FccLink.Me(first.text.toString().trim(), last.text.toString().trim(), addr.text.toString().trim(),
                city.text.toString().trim(), if (spin.selectedItemPosition > 0) states[spin.selectedItemPosition] else "",
                zip.text.toString().trim(), phone.text.toString().trim(), email.text.toString().trim()))
            Toast.makeText(this, "Saved", Toast.LENGTH_SHORT).show()
            finish()
        })
    }
}
