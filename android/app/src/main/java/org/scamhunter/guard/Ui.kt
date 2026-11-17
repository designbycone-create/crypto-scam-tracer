package org.scamhunter.guard

import android.app.Activity
import android.content.Context
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.text.InputType
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

/** Large-print, high-contrast building blocks: every screen is readable without glasses. */
object Ui {
    const val RED = 0xFFB00020.toInt()
    const val AMBER = 0xFFF2B01E.toInt()
    const val GREEN = 0xFF1E7D32.toInt()
    const val BLUE = 0xFF0B57D0.toInt()
    const val INK = 0xFF111111.toInt()

    fun page(a: Activity, title: String): LinearLayout {
        val col = LinearLayout(a).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(a, 20), dp(a, 24), dp(a, 20), dp(a, 40)) }
        col.addView(text(a, title, 30f, bold = true))
        a.setContentView(ScrollView(a).apply { addView(col); setBackgroundColor(Color.WHITE) })
        return col
    }

    fun dp(c: Context, v: Int) = TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v.toFloat(), c.resources.displayMetrics).toInt()

    fun text(c: Context, s: String, size: Float = 21f, bold: Boolean = false, color: Int = INK) = TextView(c).apply {
        text = s; textSize = size; setTextColor(color); setLineSpacing(0f, 1.15f)
        if (bold) typeface = Typeface.DEFAULT_BOLD
        setPadding(0, dp(c, 8), 0, dp(c, 8))
    }

    fun button(c: Context, label: String, color: Int = BLUE, onClick: () -> Unit) = Button(c).apply {
        text = label; textSize = 23f; isAllCaps = false; setTextColor(if (color == AMBER) INK else Color.WHITE)
        background = GradientDrawable().apply { setColor(color); cornerRadius = dp(c, 14).toFloat() }
        minHeight = dp(c, 72)
        setOnClickListener { onClick() }
        layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(c, 14) }
    }

    fun banner(c: Context, title: String, body: String, level: String): View {
        val bg = when (level) { "stop", "high" -> RED; "caution", "medium" -> AMBER; "low" -> 0xFFE8EEF8.toInt(); else -> 0xFFE8F4EA.toInt() }
        val fg = if (bg == RED) Color.WHITE else INK
        return LinearLayout(c).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(c, 18), dp(c, 14), dp(c, 18), dp(c, 14))
            background = GradientDrawable().apply { setColor(bg); cornerRadius = dp(c, 14).toFloat() }
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply { topMargin = dp(c, 16) }
            addView(text(c, title, 28f, bold = true, color = fg))
            if (body.isNotBlank()) addView(text(c, body, 20f, color = fg))
        }
    }

    fun input(c: Context, hint: String, multiline: Boolean = false, phone: Boolean = false) = EditText(c).apply {
        this.hint = hint; textSize = 21f
        inputType = when {
            phone -> InputType.TYPE_CLASS_PHONE
            multiline -> InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or InputType.TYPE_TEXT_FLAG_CAP_SENTENCES
            else -> InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_WORDS
        }
        if (multiline) { minLines = 4; gravity = Gravity.TOP or Gravity.START }
    }

    fun checker(c: Context) = MsgCheck(c.assets.open("scam_rules.json").bufferedReader().use { it.readText() })
}
