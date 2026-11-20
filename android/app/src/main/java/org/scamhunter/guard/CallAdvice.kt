package org.scamhunter.guard

/**
 * What to tell the person about an incoming call. Pure code (no Android), so it's unit-tested on a computer.
 *
 * Android only asks a call-screening app about numbers that are NOT in the person's contacts, so every call
 * that reaches this is from a number they haven't saved.
 */
object CallAdvice {
    /** level: "stop" (red), "caution" (amber) or "unknown" (calm blue: not reported, just not a contact). */
    data class Advice(val level: String, val title: String, val body: String)

    const val TIPS = "Don't give codes, card numbers or personal details. Never pay with gift cards, crypto or a wire. " +
        "If it says it's your bank or the government, hang up and call the number you know."

    fun advise(r: NumberList.Rating, warnLow: Boolean, warnNotContact: Boolean): Advice? {
        fun reported() = buildString {
            append(r.headline)
            r.subject?.let { append(" as \"$it\"") }
            append(". ")
            if (r.robocall) append("Often a recorded message. ")
            append(TIPS)
        }
        return when {
            r.level == "high" -> Advice("stop", "LIKELY SCAM CALL", reported())
            r.level == "medium" || (warnLow && r.level == "low") -> Advice("caution", "Possible scam call", reported())
            warnNotContact -> Advice("unknown", "Unknown caller",
                "This number isn't in your contacts and hasn't been reported yet. Scammers change numbers often. " +
                    "If they ask for money, a code or personal details, hang up.")
            else -> null
        }
    }
}
