package org.scamhunter.desk

import android.annotation.SuppressLint
import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.net.Uri
import android.os.Bundle
import android.util.TypedValue
import android.view.Gravity
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.LinearLayout
import android.widget.TextView
import java.io.ByteArrayInputStream

/**
 * Your PC's Desk, on the phone. Every page and every check goes through RelayClient: encrypted on this
 * phone, passed along by your Worker, opened by your Desk. The WebView never talks to the internet itself.
 */
class DeskActivity : Activity() {
    private lateinit var web: WebView
    private lateinit var status: TextView
    private var client: RelayClient? = null

    private fun dp(v: Int) = TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v.toFloat(), resources.displayMetrics).toInt()

    /** "Desk online" / "Desk offline" in the app bar: a dot AND the words, never color alone. */
    private fun setOnline(on: Boolean) = runOnUiThread {
        if (!::status.isInitialized) return@runOnUiThread
        status.text = if (on) "● Desk online" else "● Desk offline"
        status.setTextColor(if (on) 0xFF5EEAD4.toInt() else 0xFFF6C453.toInt())
        status.contentDescription = if (on) "Desk online" else "Desk offline"
    }

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val p = Store.pairing(this)
        if (p == null) {
            startActivity(Intent(this, PairActivity::class.java))
            finish()
            return
        }
        client = RelayClient(p)

        // Night Desk app bar: one row, at least 64dp: the name, and whether the Desk is reachable. Settings is a row on Home.
        val bar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL; minimumHeight = dp(64)
            setPadding(dp(16), dp(8), dp(12), dp(8)); setBackgroundColor(0xFF071018.toInt())
        }
        bar.addView(TextView(this).apply {
            text = "ScamHunter"; textSize = 21f; typeface = Typeface.DEFAULT_BOLD; setTextColor(0xFFF7F8FB.toInt())
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            minHeight = dp(48); gravity = Gravity.CENTER_VERTICAL
            setOnClickListener { web.loadUrl(Html.BASE + "/") }
            contentDescription = "ScamHunter, go to Home"
        })
        status = TextView(this).apply {
            textSize = 18f; typeface = Typeface.DEFAULT_BOLD; minHeight = dp(48); gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(14), 0, dp(14), 0)
            background = android.graphics.drawable.GradientDrawable().apply {
                setColor(0xFF0E1724.toInt()); cornerRadius = dp(24).toFloat(); setStroke(dp(1), 0xFF3D5678.toInt())
            }
        }
        bar.addView(status)
        setOnline(true)
        val line = android.view.View(this).apply { setBackgroundColor(0xFF2C415C.toInt()) }

        web = WebView(this)
        web.setBackgroundColor(0xFF071018.toInt())
        web.settings.apply {
            javaScriptEnabled = true            // the Desk's own pages (maps, live feed) need it
            domStorageEnabled = true
            allowFileAccess = false
            allowContentAccess = false
            mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
            textZoom = Store.zoom(this@DeskActivity)
            setSupportMultipleWindows(false)
        }
        web.webViewClient = object : WebViewClient() {
            override fun shouldInterceptRequest(view: WebView, req: WebResourceRequest): WebResourceResponse {
                val u = req.url
                if (u.host != Html.HOST) return empty()            // nothing on a Desk page may load from anywhere else
                val fp = u.encodedPath ?: ""
                if (fp.startsWith("/static/fonts/")) {               // the Desk's fonts ship inside the app: no trip over the relay
                    val name = fp.substringAfterLast('/')
                    return if (Regex("[a-z0-9-]+\\.woff2").matches(name)) try {
                        WebResourceResponse("font/woff2", null, 200, "OK", mapOf("Cache-Control" to "max-age=31536000"), assets.open("fonts/$name"))
                    } catch (e: Exception) { empty() } else empty()
                }
                if (req.method != "GET") return page(Html.problem("error", "unsupported request"))
                val full = (u.encodedPath ?: "/") + (u.encodedQuery?.let { "?$it" } ?: "")
                val (path, body) = Html.splitPost(full)
                val out = client!!.call(if (body != null) "POST" else "GET", path, body ?: ByteArray(0),
                    if (body != null) "application/x-www-form-urlencoded" else "")
                return when (out) {
                    is RelayClient.Outcome.Fail -> { setOnline(false); page(Html.problem(out.kind, out.detail)) }
                    is RelayClient.Outcome.Ok -> {
                        setOnline(true)
                        val r = out.r
                        if (r.status in 300..399) page(Html.redirect(r.location))
                        else {
                            val mime = r.ctype.substringBefore(';').trim().ifEmpty { "application/octet-stream" }
                            val charset = Regex("charset=([\\w-]+)", RegexOption.IGNORE_CASE).find(r.ctype)?.groupValues?.get(1) ?: "utf-8"
                            val data = if (mime == "text/html") Html.inject(r.body) else r.body
                            WebResourceResponse(mime, charset, r.status, reason(r.status), mapOf("Cache-Control" to "no-store"), ByteArrayInputStream(data))
                        }
                    }
                }
            }

            override fun shouldOverrideUrlLoading(view: WebView, req: WebResourceRequest): Boolean {
                val u = req.url
                if (u.host == Html.HOST && u.scheme == "https") return false
                if (u.scheme == "shapp") {                                   // "Phone app settings" on the Desk's Home page
                    settings()
                    return true
                }
                if (u.scheme == "shtd") {
                    Store.forget(this@DeskActivity)
                    startActivity(Intent(this@DeskActivity, PairActivity::class.java))
                    finish()
                    return true
                }
                if (u.scheme == "http" || u.scheme == "https") {              // links out (sources, explorers): the phone's browser
                    try { startActivity(Intent(Intent.ACTION_VIEW, u)) } catch (e: Exception) {}
                }
                return true
            }
        }

        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setBackgroundColor(0xFF0B1220.toInt()) }
        root.addView(bar)
        root.addView(line, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(1)))
        root.addView(web, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f))
        root.setBackgroundColor(0xFF071018.toInt())        // the strip behind the status bar matches the app's top bar
        Insets.fit(root)
        setContentView(root)
        if (savedInstanceState != null) web.restoreState(savedInstanceState) else web.loadUrl(Html.BASE + "/")
        App.showLastCrash(this)
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        if (::web.isInitialized) web.saveState(outState)
    }

    private fun empty() = WebResourceResponse("text/plain", "utf-8", 204, "No Content", emptyMap(), ByteArrayInputStream(ByteArray(0)))

    private fun page(b: ByteArray) = WebResourceResponse("text/html", "utf-8", 200, "OK", mapOf("Cache-Control" to "no-store"), ByteArrayInputStream(b))

    private fun reason(s: Int) = when (s) {
        200 -> "OK"; 403 -> "Forbidden"; 404 -> "Not Found"; 413 -> "Too Large"; 500 -> "Error"; 502 -> "Bad Gateway"; else -> "Status"
    }

    private fun zoom(d: Int) {
        Store.setZoom(this, Store.zoom(this) + d)
        web.settings.textZoom = Store.zoom(this)
    }

    private fun settings() {
        val items = arrayOf("Larger text (now ${Store.zoom(this)}%)", "Smaller text", "Reload this page", "Unpair this phone")
        AlertDialog.Builder(this).setTitle("Phone app settings")
            .setItems(items) { _, which ->
                when (which) {
                    0 -> zoom(15)
                    1 -> zoom(-15)
                    2 -> web.reload()
                    3 -> unpair()
                }
            }
            .setPositiveButton("Close", null).show()
    }

    private fun unpair() {
        AlertDialog.Builder(this).setTitle("Unpair this phone?")
            .setMessage("If you stop using this phone, unpair it here and on the computer (Settings, then Phone app, then Unpair).")
            .setPositiveButton("Close", null)
            .setNegativeButton("Unpair this phone") { _, _ ->
                AlertDialog.Builder(this).setMessage("Forget your Desk on this phone? You'll need a new code from the computer to pair again.")
                    .setPositiveButton("Forget it") { _, _ ->
                        Store.forget(this)
                        startActivity(Intent(this, PairActivity::class.java))
                        finish()
                    }.setNegativeButton("Cancel", null).show()
            }.show()
    }

    @Deprecated("Back handling for plain Activity")
    override fun onBackPressed() {
        if (::web.isInitialized && web.canGoBack()) web.goBack() else {
            @Suppress("DEPRECATION")
            super.onBackPressed()
        }
    }
}
