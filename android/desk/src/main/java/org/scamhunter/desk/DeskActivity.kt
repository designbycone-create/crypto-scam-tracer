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
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import java.io.ByteArrayInputStream

/**
 * Your PC's Desk, on the phone. Every page and every check goes through RelayClient: encrypted on this
 * phone, passed along by your Worker, opened by your Desk. The WebView never talks to the internet itself.
 */
class DeskActivity : Activity() {
    private lateinit var web: WebView
    private var client: RelayClient? = null

    private fun dp(v: Int) = TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v.toFloat(), resources.displayMetrics).toInt()

    private fun barButton(label: String, onClick: () -> Unit) = Button(this).apply {
        text = label; textSize = 18f; isAllCaps = false; setTextColor(Color.WHITE); setBackgroundColor(0xFF1B2A44.toInt())
        minWidth = dp(52); minimumWidth = dp(52)
        layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.WRAP_CONTENT, dp(48)).apply { leftMargin = dp(6) }
        setOnClickListener { onClick() }
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

        val bar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(12), dp(8), dp(8), dp(8)); setBackgroundColor(0xFF070D18.toInt())
        }
        bar.addView(TextView(this).apply {
            text = "THREAT DESK"; textSize = 17f; typeface = Typeface.DEFAULT_BOLD; setTextColor(0xFF22D3EE.toInt())
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
            setOnClickListener { web.loadUrl(Html.BASE + "/") }
        })
        bar.addView(barButton("A−") { zoom(-15) })
        bar.addView(barButton("A+") { zoom(15) })
        bar.addView(barButton("↻") { web.reload() })
        bar.addView(barButton("⚙") { settings() })

        web = WebView(this)
        web.setBackgroundColor(0xFF0B1220.toInt())
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
                if (req.method != "GET") return page(Html.problem("error", "unsupported request"))
                val full = (u.encodedPath ?: "/") + (u.encodedQuery?.let { "?$it" } ?: "")
                val (path, body) = Html.splitPost(full)
                val out = client!!.call(if (body != null) "POST" else "GET", path, body ?: ByteArray(0),
                    if (body != null) "application/x-www-form-urlencoded" else "")
                return when (out) {
                    is RelayClient.Outcome.Fail -> page(Html.problem(out.kind, out.detail))
                    is RelayClient.Outcome.Ok -> {
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
        root.addView(web, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f))
        root.setBackgroundColor(0xFF070D18.toInt())        // the strip behind the status bar matches the app's top bar
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
        AlertDialog.Builder(this).setTitle("Threat Desk")
            .setMessage("This phone is paired with your Desk. Text size: ${Store.zoom(this)}%.\n\n" +
                "If you stop using this phone, unpair it here and on the computer (Settings → Phone app → Unpair).")
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
