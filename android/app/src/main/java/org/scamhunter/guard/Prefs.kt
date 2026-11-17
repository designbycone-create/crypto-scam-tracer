package org.scamhunter.guard

import android.content.Context

/** Settings and the last screened call, kept privately on the phone. */
object Prefs {
    private fun p(c: Context) = c.getSharedPreferences("guard", Context.MODE_PRIVATE)

    fun familyName(c: Context) = p(c).getString("family_name", "") ?: ""
    fun familyNumber(c: Context) = p(c).getString("family_number", "") ?: ""
    fun state(c: Context) = p(c).getString("state", "") ?: ""
    fun codeWord(c: Context) = p(c).getString("code_word", "") ?: ""
    fun silenceHighRisk(c: Context) = p(c).getBoolean("silence_high", false)
    fun warnUnknown(c: Context) = p(c).getBoolean("warn_unknown", false)

    fun save(c: Context, familyName: String, familyNumber: String, state: String, codeWord: String, silence: Boolean, warnUnknown: Boolean) =
        p(c).edit().putString("family_name", familyName).putString("family_number", familyNumber).putString("state", state)
            .putString("code_word", codeWord).putBoolean("silence_high", silence).putBoolean("warn_unknown", warnUnknown).apply()

    fun lastCall(c: Context, number: String, level: String, headline: String, subject: String) =
        p(c).edit().putString("last_number", number).putString("last_level", level).putString("last_headline", headline)
            .putString("last_subject", subject).putLong("last_time", System.currentTimeMillis()).apply()

    fun lastNumber(c: Context) = p(c).getString("last_number", "") ?: ""
    fun lastTime(c: Context) = p(c).getLong("last_time", 0)
}

/**
 * Phone-call recording consent by state (general information, not legal advice; check the state's law).
 * All-party: everyone on the call must agree before it's recorded.
 */
object RecordingLaw {
    val ALL_PARTY = setOf("California", "Florida", "Illinois", "Maryland", "Massachusetts", "Montana", "New Hampshire",
        "Pennsylvania", "Washington", "Connecticut", "Nevada")
    val STATES = listOf("Alabama", "Alaska", "Arizona", "Arkansas", "California", "Colorado", "Connecticut", "Delaware",
        "District of Columbia", "Florida", "Georgia", "Hawaii", "Idaho", "Illinois", "Indiana", "Iowa", "Kansas", "Kentucky",
        "Louisiana", "Maine", "Maryland", "Massachusetts", "Michigan", "Minnesota", "Mississippi", "Missouri", "Montana",
        "Nebraska", "Nevada", "New Hampshire", "New Jersey", "New Mexico", "New York", "North Carolina", "North Dakota", "Ohio",
        "Oklahoma", "Oregon", "Pennsylvania", "Rhode Island", "South Carolina", "South Dakota", "Tennessee", "Texas", "Utah",
        "Vermont", "Virginia", "Washington", "West Virginia", "Wisconsin", "Wyoming")

    fun note(state: String): String = when {
        state.isBlank() -> "Choose your state in Settings to see whether you may record calls."
        state in ALL_PARTY -> "In $state, everyone on a call must agree before it's recorded. If you want to record, first say: " +
            "\"This call is being recorded.\" Scammers usually hang up when they hear that."
        else -> "In $state, you may generally record a call you are part of. If the other person is in a state like California " +
            "or Florida, their state's stricter rule can apply, so saying \"this call is being recorded\" is the safe habit."
    } + " This is general information, not legal advice."
}
