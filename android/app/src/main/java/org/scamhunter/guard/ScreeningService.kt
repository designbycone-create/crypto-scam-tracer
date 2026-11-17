package org.scamhunter.guard

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.telecom.Call
import android.telecom.CallScreeningService

/**
 * Android's official call-screening service. For each incoming call from a number that isn't in
 * your contacts, Android hands us the NUMBER only (never audio). We look it up in the FTC list on
 * the phone and warn you with a notification before you answer. The call always rings through:
 * a warning, not a block, so a real call is never lost. Optionally, high-risk calls ring silently.
 */
class ScreeningService : CallScreeningService() {

    override fun onScreenCall(details: Call.Details) {
        val allow = CallResponse.Builder()
        try {
            if (details.callDirection == Call.Details.DIRECTION_INCOMING) {
                val number = details.handle?.schemeSpecificPart
                val meta = NumberList.meta(this)
                val hit = NumberList.lookup(this, number)
                val r = NumberList.rate(hit, meta.optInt("days", 30))
                Prefs.lastCall(this, number ?: "", r.level, r.headline, r.subject ?: "")
                if (r.level == "high" && Prefs.silenceHighRisk(this)) allow.setSilenceCall(true)
                if (r.level == "high" || r.level == "medium" || (Prefs.warnUnknown(this) && r.level != "none")) {
                    warn(this, number ?: "unknown number", r)
                }
            }
        } catch (e: Exception) {
            // never let a lookup problem interfere with a phone call
        }
        respondToCall(details, allow.build())
    }

    companion object {
        const val CHANNEL = "scam_calls"

        fun channel(ctx: Context) {
            val nm = ctx.getSystemService(NotificationManager::class.java)
            if (nm.getNotificationChannel(CHANNEL) == null) {
                nm.createNotificationChannel(NotificationChannel(CHANNEL, "Scam call warnings", NotificationManager.IMPORTANCE_HIGH).apply {
                    description = "Warnings about incoming calls from numbers people have reported"
                })
            }
        }

        fun warn(ctx: Context, number: String, r: NumberList.Rating) {
            channel(ctx)
            val title = if (r.level == "high") "LIKELY SCAM CALL" else "Possible scam call"
            val body = buildString {
                append(r.headline)
                r.subject?.let { append(" as \"$it\"") }
                append(". ")
                if (r.robocall) append("Often a recorded message. ")
                append("Don't give codes, card numbers or personal details. Never pay with gift cards, crypto or a wire. " +
                    "If it says it's your bank or the government, hang up and call the number you know.")
            }
            val open = PendingIntent.getActivity(ctx, 0, Intent(ctx, ReportActivity::class.java).putExtra("number", number),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
            val n = Notification.Builder(ctx, CHANNEL)
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setContentTitle("$title: $number")
                .setContentText(r.headline)
                .setStyle(Notification.BigTextStyle().bigText(body))
                .setCategory(Notification.CATEGORY_CALL)
                .setContentIntent(open)
                .setAutoCancel(true)
                .addAction(Notification.Action.Builder(null, "Report this call", open).build())
                .build()
            try { ctx.getSystemService(NotificationManager::class.java).notify(number.hashCode(), n) } catch (e: SecurityException) { }
        }
    }
}
