package org.scamhunter.guard

import android.app.Activity
import android.app.role.RoleManager
import android.content.Intent
import android.os.Bundle
import java.text.DateFormat
import java.util.Date

class MainActivity : Activity() {
    private var triedList = false

    override fun onResume() {
        super.onResume()
        val col = Ui.page(this, "ScamHunter Guard")
        val rm = getSystemService(RoleManager::class.java)
        val screening = rm.isRoleHeld(RoleManager.ROLE_CALL_SCREENING)
        val meta = NumberList.meta(this)
        val count = meta.optInt("count", 0)

        if (!screening) {
            col.addView(Ui.banner(this, "Call warnings are OFF", "Turn them on so the app can warn you about reported scam numbers " +
                "before you answer. The app only sees the caller's number, never the call itself.", "caution"))
            col.addView(Ui.button(this, "Turn on call warnings", Ui.AMBER) {
                startActivityForResult(rm.createRequestRoleIntent(RoleManager.ROLE_CALL_SCREENING), 1)
            })
        } else {
            col.addView(Ui.banner(this, "Call warnings are ON",
                if (count > 0) "Watching for $count reported numbers (FTC list up to ${meta.optString("to")})."
                else "Getting the list of reported numbers (needs the internet)...", if (count > 0) "ok" else "caution"))
            if (!RingWarning.canShow(this)) {
                col.addView(Ui.banner(this, "One more step", "Allow \"Appear on top\" so a big warning shows over the call " +
                    "while it rings. On the next screen, find ScamHunter Guard and turn it on.", "caution"))
                col.addView(Ui.button(this, "Turn on \"Appear on top\"", Ui.AMBER) { startActivity(RingWarning.settingsIntent(this)) })
            }
        }
        // a fresh install has no list yet: fetch it now instead of waiting for the daily Wi-Fi update
        if (count == 0 && !triedList) {
            triedList = true       // once per screen: no retry loop when there's no internet
            Thread {
                val got = try { NumberList.download(this) } catch (e: Exception) { 0 }
                if (got > 0) runOnUiThread { if (!isFinishing) recreate() }
            }.start()
        }
        col.addView(Ui.button(this, "Am I being scammed right now?", Ui.RED) { startActivity(Intent(this, HelpActivity::class.java)) })
        col.addView(Ui.button(this, "Report a call") { startActivity(Intent(this, ReportActivity::class.java)) })
        col.addView(Ui.button(this, "Check a text, email or message") { startActivity(Intent(this, CheckActivity::class.java)) })
        col.addView(Ui.button(this, "Check a phone number") {
            startActivity(Intent(this, CheckActivity::class.java).putExtra("mode", "number"))
        })
        col.addView(Ui.button(this, "Settings and family contact", Ui.INK) { startActivity(Intent(this, SettingsActivity::class.java)) })

        val last = Prefs.lastNumber(this)
        if (last.isNotBlank()) {
            col.addView(Ui.text(this, "Last call checked: $last, " +
                DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(Date(Prefs.lastTime(this))), 17f))
        }
        col.addView(Ui.text(this, "Free and private: the app never sends your calls or messages anywhere, never asks for money, " +
            "and never sends anything without you pressing Send.", 16f))
        if (android.os.Build.VERSION.SDK_INT >= 33 && checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != 0) {
            requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 2)
        }
        ListJob.schedule(this)
    }

    override fun onCreate(savedInstanceState: Bundle?) { super.onCreate(savedInstanceState); ScreeningService.channel(this) }
}
