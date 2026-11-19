package org.scamhunter.desk

import android.app.Activity
import android.app.AlertDialog
import android.app.Application
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import java.io.File

/**
 * If the app ever crashes, the error is saved on the phone (never sent anywhere) and shown the next time it
 * opens, so it can be read out or screenshotted and fixed properly.
 */
class App : Application() {
    override fun onCreate() {
        super.onCreate()
        val previous = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { t, e ->
            try {
                val trace = android.util.Log.getStackTraceString(e)
                File(filesDir, CRASH).writeText("ScamHunter Threat Desk ${BuildConfigInfo.version(this)} on Android ${Build.VERSION.RELEASE} " +
                    "(${Build.MANUFACTURER} ${Build.MODEL})\nThread: ${t.name}\n\n$trace".take(6000))
            } catch (_: Exception) {}
            previous?.uncaughtException(t, e)
        }
    }

    companion object {
        const val CRASH = "last_crash.txt"

        /** Show (once) what went wrong last time, with a Copy button. */
        fun showLastCrash(a: Activity) {
            val f = File(a.filesDir, CRASH)
            if (!f.exists()) return
            val text = f.readText()
            f.delete()
            AlertDialog.Builder(a).setTitle("The app closed last time")
                .setMessage("Please send this to the person fixing ScamHunter (a screenshot is fine). It contains no personal data.\n\n" + text.take(1800))
                .setPositiveButton("Copy") { _, _ ->
                    (a.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager).setPrimaryClip(ClipData.newPlainText("ScamHunter crash", text))
                }
                .setNegativeButton("Close", null).show()
        }
    }
}

object BuildConfigInfo {
    fun version(c: Context): String = try {
        c.packageManager.getPackageInfo(c.packageName, 0).versionName ?: "?"
    } catch (_: Exception) { "?" }
}
