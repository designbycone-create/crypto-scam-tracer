package org.scamhunter.desk

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.text.InputType
import android.util.TypedValue
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import com.google.zxing.integration.android.IntentIntegrator

/** Pair this phone with the Desk: scan the QR code shown on the computer (or paste the code under it). */
class PairActivity : Activity() {
    private lateinit var status: TextView

    private fun dp(v: Int) = TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v.toFloat(), resources.displayMetrics).toInt()

    private fun text(s: String, size: Float = 21f, bold: Boolean = false, color: Int = 0xFFE8EEF8.toInt()) = TextView(this).apply {
        text = s; textSize = size; setTextColor(color); setLineSpacing(0f, 1.15f); setPadding(0, dp(8), 0, dp(8))
        if (bold) typeface = Typeface.DEFAULT_BOLD
    }

    private fun button(label: String, primary: Boolean, onClick: () -> Unit) = Button(this).apply {
        text = label; textSize = 22f; isAllCaps = false
        setTextColor(if (primary) 0xFF04111C.toInt() else Color.WHITE)
        background = GradientDrawable().apply { setColor(if (primary) 0xFF22D3EE.toInt() else 0xFF1B2A44.toInt()); cornerRadius = dp(14).toFloat() }
        minHeight = dp(70)
        layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply { topMargin = dp(14) }
        setOnClickListener { onClick() }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)   // no screenshots of a pairing code
        val col = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(22), dp(28), dp(22), dp(40)) }
        col.addView(text("SCAMHUNTER  THREAT DESK", 16f, bold = true, color = 0xFF22D3EE.toInt()))
        col.addView(text("Pair with my Desk", 30f, bold = true))
        col.addView(text("On your computer, open the Desk, then Settings → Phone app → Pair my phone. A square code appears. Scan it here."))
        col.addView(button("Scan the code", true) {
            try {
                IntentIntegrator(this).setDesiredBarcodeFormats(IntentIntegrator.QR_CODE).setPrompt("Point at the code on your Desk")
                    .setBeepEnabled(false).setOrientationLocked(false).initiateScan()
            } catch (e: Exception) {
                status.setTextColor(0xFFFF8AA0.toInt())
                status.text = "The scanner couldn't start: ${e.javaClass.simpleName}: ${e.message}"
            }
        })
        col.addView(text("Can't scan? Copy the code shown under the picture on the computer and paste it here:", 18f, color = 0xFF9FB0C8.toInt()))
        val paste = EditText(this).apply {
            textSize = 18f; setTextColor(Color.WHITE); setHintTextColor(0xFF6B7C96.toInt()); hint = "shtd1:..."
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
        }
        col.addView(paste)
        col.addView(button("Pair with this code", false) { use(paste.text.toString()) })
        status = text("", 20f)
        col.addView(status)
        col.addView(text("The code connects only this phone to your own Desk. Everything between them is encrypted; " +
            "your Cloudflare Worker passes it along without being able to read it.", 16f, color = 0xFF9FB0C8.toInt()))
        setContentView(ScrollView(this).apply { addView(col); setBackgroundColor(0xFF0B1220.toInt()) })
        App.showLastCrash(this)
    }

    @Deprecated("Activity result API from the scanner library")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        val r = IntentIntegrator.parseActivityResult(requestCode, resultCode, data)
        if (r != null) {
            r.contents?.let { use(it) }
            return
        }
        @Suppress("DEPRECATION")
        super.onActivityResult(requestCode, resultCode, data)
    }

    private fun use(code: String) {
        val p = Pairing.parse(code)
        if (p == null) {
            status.setTextColor(0xFFFF8AA0.toInt())
            status.text = "That isn't a ScamHunter pairing code. Make a new one on the Desk and try again."
            return
        }
        status.setTextColor(0xFFE8EEF8.toInt())
        status.text = "Checking with your Desk…"
        Thread {
            val out = RelayClient(p).call("GET", "/live.json")
            runOnUiThread {
                when {
                    out is RelayClient.Outcome.Ok || (out is RelayClient.Outcome.Fail && out.kind in setOf("offline", "timeout")) -> {
                        Store.save(this, p)
                        if (out is RelayClient.Outcome.Fail) {
                            status.text = "Paired. Your Desk isn't answering right now, so the app will show that until the computer is on."
                        }
                        startActivity(Intent(this, DeskActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK or Intent.FLAG_ACTIVITY_NEW_TASK))
                        finish()
                    }
                    out is RelayClient.Outcome.Fail && out.kind == "unpaired" -> {
                        status.setTextColor(0xFFFF8AA0.toInt())
                        status.text = "That code is no longer valid (a newer one was made, or the phone was unpaired). Make a new one on the Desk."
                    }
                    else -> {
                        status.setTextColor(0xFFFF8AA0.toInt())
                        status.text = "Couldn't reach your Worker: " + ((out as? RelayClient.Outcome.Fail)?.detail ?: "") + ". Check the phone's internet and try again."
                    }
                }
            }
        }.start()
    }
}
