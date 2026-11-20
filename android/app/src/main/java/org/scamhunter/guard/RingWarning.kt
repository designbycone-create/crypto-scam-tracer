package org.scamhunter.guard

import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.PixelFormat
import android.graphics.drawable.GradientDrawable
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.view.Gravity
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.view.WindowManager
import android.widget.LinearLayout

/**
 * A large warning card shown on top of the incoming-call screen while the phone rings, so the person sees it
 * before answering. Needs Android's "Appear on top" permission, which the person turns on once. Without it, the
 * app falls back to a notification. The card never blocks the call: the phone keeps ringing and the person can
 * still answer, decline or close the card. It closes by itself after a minute.
 */
object RingWarning {
    private const val SHOW_MS = 60_000L
    private val main = Handler(Looper.getMainLooper())
    private var shown: View? = null

    fun canShow(c: Context) = Settings.canDrawOverlays(c)

    fun settingsIntent(c: Context) =
        Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION, android.net.Uri.parse("package:${c.packageName}"))

    /** Returns false if it couldn't be shown (no permission or the system refused), so the caller can notify instead. */
    fun show(ctx: Context, number: String, a: CallAdvice.Advice, onFail: () -> Unit = {}): Boolean {
        if (!canShow(ctx)) return false
        val c = ctx.applicationContext
        main.post {
            try {
                hide(c)
                val wm = c.getSystemService(WindowManager::class.java)
                val bg = when (a.level) { "stop" -> Ui.RED; "caution" -> Ui.AMBER; else -> 0xFF0B57D0.toInt() }
                val fg = if (a.level == "caution") Ui.INK else Color.WHITE
                val card = LinearLayout(c).apply {
                    orientation = LinearLayout.VERTICAL
                    setPadding(Ui.dp(c, 20), Ui.dp(c, 16), Ui.dp(c, 20), Ui.dp(c, 16))
                    background = GradientDrawable().apply { setColor(bg); cornerRadius = Ui.dp(c, 18).toFloat(); setStroke(Ui.dp(c, 3), Color.WHITE) }
                    addView(Ui.text(c, "ScamHunter Guard", 16f, bold = true, color = fg))
                    addView(Ui.text(c, a.title, 30f, bold = true, color = fg))
                    addView(Ui.text(c, number, 24f, bold = true, color = fg))
                    addView(Ui.text(c, a.body, 19f, color = fg))
                    val row = LinearLayout(c).apply { orientation = LinearLayout.HORIZONTAL }
                    val close = Ui.button(c, "Close", Ui.INK, small = true) { hide(c) }
                    val report = Ui.button(c, "Report it", if (a.level == "stop") Ui.INK else Ui.RED, small = true) {
                        hide(c)
                        c.startActivity(Intent(c, ReportActivity::class.java).putExtra("number", number)
                            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
                    }
                    listOf(close, report).forEachIndexed { i, b ->
                        b.layoutParams = LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f).apply {
                            topMargin = Ui.dp(c, 10); if (i == 1) marginStart = Ui.dp(c, 10)
                        }
                        row.addView(b)
                    }
                    addView(row)
                }
                val frame = LinearLayout(c).apply { setPadding(Ui.dp(c, 10), 0, Ui.dp(c, 10), 0); addView(card, MATCH_PARENT, WRAP_CONTENT) }
                val lp = WindowManager.LayoutParams(MATCH_PARENT, WRAP_CONTENT,
                    WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
                    WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
                    PixelFormat.TRANSLUCENT).apply { gravity = Gravity.TOP; y = Ui.dp(c, 64) }   // below the status bar and caller's name
                wm.addView(frame, lp)
                shown = frame
                main.postDelayed({ if (shown === frame) hide(c) }, SHOW_MS)
            } catch (e: Exception) {
                shown = null
                onFail()           // e.g. the system refused the window: fall back to a notification
            }
        }
        return true
    }

    fun hide(c: Context) {
        val v = shown ?: return
        shown = null
        try { c.getSystemService(WindowManager::class.java).removeView(v) } catch (e: Exception) { }
    }
}
