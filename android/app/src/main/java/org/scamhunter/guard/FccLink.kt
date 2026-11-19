package org.scamhunter.guard

import java.net.URLEncoder

/**
 * Builds a link that opens the FCC's own complaint form (consumercomplaints.fcc.gov, Phone > Unwanted Calls)
 * with the answers already filled in, using the form's standard pre-fill feature (Zendesk "tf_" URL parameters).
 *
 * Nothing is sent by the app. The person reads the filled form, ticks the FCC's "Attest" box and taps Submit
 * themselves: the complaint must come from them. This builder deliberately never fills the Attest box, and leaves
 * the yes/no questions only the person can answer (did they claim to be a company, did you give permission...).
 *
 * Field ids and answer values were read from the live form on 2026-11-19. If the FCC changes its form, fields it no
 * longer has are simply ignored by the site; the report is also copied, so the person can still paste it.
 */
object FccLink {
    const val FORM_URL = "https://consumercomplaints.fcc.gov/hc/en-us/requests/new"
    const val PHONE_FORM = "39744"

    // custom field ids on the Phone form
    const val F_PHONE_ISSUE = "22619354"
    const val F_UNWANTED_SUB = "360000167206"
    const val F_PHONE_METHOD = "22781220"
    const val F_PHONE_TYPE = "22659804"
    const val F_NUMBER_RECEIVED_ON = "22625614"
    const val F_DATE = "22591154"
    const val F_TIME = "22732340"
    const val F_CALL_TYPE = "22787840"
    const val F_HAD_CALLER_ID = "22787920"
    const val F_CALLER_ID_NUMBER = "22659864"
    const val F_FIRST = "22539594"
    const val F_LAST = "22704720"
    const val F_ADDRESS1 = "22554824"
    const val F_CITY = "22554844"
    const val F_STATE = "22540114"
    const val F_ZIP = "22540124"
    const val F_CONTACT_PHONE = "22615094"
    const val F_ON_BEHALF = "22636844"
    const val F_ATTEST = "22625624"          // never filled: the person ticks it
    // Not filled on purpose: "Telephone Number Subject of Complaint" (22664804) is hidden for unwanted calls,
    // so a value there would be sent without the person seeing it. Every value we fill is one they can see.

    /** What kind of contact it was, as the person told the app. */
    enum class Kind(val tag: String) {
        RECORDING("prerecorded_voice_type_of_call_telemarketing"),
        PERSON("live_voice_type_of_call_telemarketing"),
        TEXT("text_messaage_type_of_call_telemarketing"),   // sic: the FCC's own spelling
    }

    data class Me(val first: String = "", val last: String = "", val address: String = "", val city: String = "",
                  val state: String = "", val zip: String = "", val phone: String = "", val email: String = "") {
        fun isEmpty() = listOf(first, last, address, city, zip, phone, email).all { it.isBlank() }
    }

    data class Report(
        val callerNumber: String?,      // 10 digits, or null if unknown
        val date: String,               // yyyy-MM-dd
        val time: String,               // e.g. "10:30 AM"
        val description: String,
        val kind: Kind? = null,
        val me: Me = Me(),
    )

    /** "District of Columbia" -> "district_of_columbia" (the form's own tag rule, checked for all 50 states + DC). */
    fun stateTag(state: String): String = state.trim().lowercase().replace(Regex("\\s+"), "_")

    /** The form refuses values containing < or > (and long links are fragile), so clean and trim every value. */
    fun clean(v: String, max: Int = 200): String = v.replace('<', '(').replace('>', ')').trim().take(max)

    fun digits(v: String): String = v.filter { it.isDigit() }.let { if (it.length == 11 && it.startsWith("1")) it.drop(1) else it }

    fun params(r: Report): List<Pair<String, String>> {
        val p = mutableListOf<Pair<String, String>>()
        fun add(k: String, v: String?) { if (!v.isNullOrBlank()) p += k to v }
        fun cf(id: String, v: String?) = add("tf_$id", v)
        add("ticket_form_id", PHONE_FORM)
        add("tf_subject", clean("Unwanted call" + (r.callerNumber?.let { " from $it" } ?: ""), 120))
        add("tf_description", clean(r.description, 1500))
        cf(F_PHONE_ISSUE, "telemarketing_phone")
        cf(F_UNWANTED_SUB, "phone_unwanted_calls_all_other_unwanted_calls")
        cf(F_PHONE_METHOD, "wireless_phone")                                  // the app runs on a cell phone
        cf(F_PHONE_TYPE, "residential_personal_phone_type_location")
        cf(F_DATE, r.date)
        cf(F_TIME, clean(r.time, 20))
        cf(F_CALL_TYPE, r.kind?.tag)
        if (!r.callerNumber.isNullOrBlank()) {
            cf(F_HAD_CALLER_ID, "yes_caller_id_information")
            cf(F_CALLER_ID_NUMBER, r.callerNumber)
        }
        val me = r.me
        val myPhone = digits(me.phone).ifBlank { null }
        cf(F_NUMBER_RECEIVED_ON, myPhone)
        cf(F_CONTACT_PHONE, myPhone)
        cf(F_FIRST, clean(me.first, 60)); cf(F_LAST, clean(me.last, 60))
        cf(F_ADDRESS1, clean(me.address, 120)); cf(F_CITY, clean(me.city, 60))
        cf(F_STATE, if (me.state.isBlank()) null else stateTag(me.state))
        cf(F_ZIP, clean(me.zip, 10))
        add("tf_anonymous_requester_email", clean(me.email, 120))
        if (!me.isEmpty()) cf(F_ON_BEHALF, "no_filing_on_behalf")             // their own details => their own complaint
        return p
    }

    fun url(r: Report): String = FORM_URL + "?" + params(r).joinToString("&") { (k, v) -> "$k=${enc(v)}" }

    // URLEncoder writes spaces as '+'; the form wants %20 (a '+' would show up as a plus sign).
    private fun enc(v: String) = URLEncoder.encode(v, "UTF-8").replace("+", "%20")
}
