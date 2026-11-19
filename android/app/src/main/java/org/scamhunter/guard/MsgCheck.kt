package org.scamhunter.guard

import org.json.JSONArray
import org.json.JSONObject
import java.net.URI
import java.util.regex.Pattern

/**
 * The same scam-message checker as the ScamHunter Threat Desk (shield/msgcheck.py), driven by the same
 * rules file (assets/scam_rules.json, exported by tools/export_mobile_rules.py). A unit test holds
 * the two to identical verdicts on a shared sample of messages.
 */
class MsgCheck(rulesJson: String) {

    data class Finding(val weight: Int, val why: String, val rule: String)
    data class Result(val verdict: String, val level: String, val score: Int, val findings: List<Finding>, val types: List<String>)

    private class Rule(val id: String, val weight: Int, val why: String, val rx: Pattern)

    private val rules: List<Rule>
    private val decisive: Set<String>
    private val shorteners: Set<String>
    private val riskyTlds: Set<String>
    private val brands: Map<String, List<String>>
    private val urlRx: Pattern
    private val hidden: Pattern
    private val badDomains: Map<String, String>
    private val badAddresses: Map<String, String>

    init {
        val j = JSONObject(rulesJson)
        val flags = Pattern.CASE_INSENSITIVE or Pattern.DOTALL or Pattern.MULTILINE or Pattern.UNICODE_CASE
        rules = j.getJSONArray("rules").objs().map {
            Rule(it.getString("id"), it.getInt("weight"), it.getString("why"), Pattern.compile(it.getString("pattern"), flags))
        }
        decisive = j.getJSONArray("decisive").strs().toSet()
        shorteners = j.getJSONArray("shorteners").strs().toSet()
        riskyTlds = j.getJSONArray("risky_tlds").strs().toSet()
        val b = j.getJSONObject("brands")
        brands = b.keys().asSequence().associateWith { b.getJSONArray(it).strs() }
        urlRx = Pattern.compile(j.getString("url_pattern"), Pattern.CASE_INSENSITIVE)
        hidden = Pattern.compile(j.getString("hidden_chars"))
        val camp = j.getJSONObject("campaign")
        badDomains = camp.getJSONObject("domains").toMap()
        badAddresses = camp.getJSONObject("addresses").toMap()
    }

    private fun registered(host: String): String {
        val p = host.split(".")
        return if (p.size > 2 && p[p.size - 2] in setOf("co", "com", "org", "net", "gov") && p.last().length == 2)
            p.takeLast(3).joinToString(".") else p.takeLast(2).joinToString(".")
    }

    /** (weight, why) for one link; weight 4 = a decisive bad link, as on the Desk. */
    fun checkLink(raw: String): List<Pair<Int, String>> {
        val u = if (Regex("^https?://", RegexOption.IGNORE_CASE).containsMatchIn(raw)) raw else "http://$raw"
        val uri = try { URI(u) } catch (e: Exception) { return listOf(2 to "The link $raw is malformed.") }
        val host = (uri.host ?: return emptyList()).lowercase().trimEnd('.')
        val out = mutableListOf<Pair<Int, String>>()
        badDomains.entries.firstOrNull { host == it.key || host.endsWith("." + it.key) }?.let {
            out += 4 to "The link goes to $host, known attacker infrastructure (${it.value})."
        }
        val reg = registered(host)
        if (Regex("[\\d.]+").matches(host)) out += 2 to "The link goes to a bare number address ($host) instead of a company name."
        if (host.startsWith("xn--") || host.contains(".xn--")) out += 2 to "The link $host uses look-alike international letters."
        if (reg in shorteners) out += 1 to "The link is shortened ($reg), which hides where it really goes."
        if ((uri.rawAuthority ?: "").contains("@")) out += 2 to "The link hides its real destination after an @ sign."
        val tld = host.substringAfterLast(".")
        val flat = host.replace(Regex("[^a-z0-9]"), "")
        for ((brand, real) in brands) {
            if (brand in flat && reg !in real && real.none { host == it || host.endsWith(".$it") }) {
                out += 4 to "The link mentions $brand but goes to $reg, which isn't $brand's website."
                break
            }
        }
        if (tld in riskyTlds && out.isEmpty()) out += 1 to "The link uses a web address ending (.$tld) that scammers favor."
        return out
    }

    fun check(text: String): Result {
        val t = text.take(20000)
        val flat = hidden.matcher(t).replaceAll("")
        val findings = mutableListOf<Finding>()
        val types = mutableListOf<String>()
        for (r in rules) if (r.rx.matcher(flat).find()) { findings += Finding(r.weight, r.why, r.id); types += r.id }
        if (flat != t) findings += Finding(2, "The message hides invisible characters, a trick used to slip past spam filters.", "hidden_chars")
        val seen = mutableSetOf<String>()
        val m = urlRx.matcher(flat)
        while (m.find()) {
            val raw = m.group(1).trimEnd('.', ',', ';', ':', '!', '?')
            if (!seen.add(raw.lowercase())) continue
            for ((w, why) in checkLink(raw)) findings += Finding(minOf(w, 3), why, if (w >= 4) "bad_link" else "link")
        }
        for (a in addresses(flat)) {
            val label = badAddresses[norm(a)]
            if (label != null) findings += Finding(3, "It contains a known scammer's address: $label.", "bad_address")
            else if (Regex("^(0x|bc1|ltc1|T|r)").containsMatchIn(a))      // clear wallet-address shapes only
                findings += Finding(1, "It contains a wallet address. Never send to an address from a message you didn't expect.", "address")
        }
        val strong = findings.count { it.weight >= 3 }
        val score = findings.sumOf { it.weight }
        val isDecisive = findings.any { it.rule in decisive }
        val (verdict, level) = when {
            isDecisive || strong >= 2 || (strong >= 1 && score >= 5) || score >= 7 -> "LIKELY SCAM" to "stop"
            strong >= 1 || score >= 3 -> "SUSPICIOUS" to "caution"
            else -> "NO RED FLAGS FOUND" to "info"
        }
        return Result(verdict, level, score, findings.sortedByDescending { it.weight }, types)
    }

    fun advice(r: Result): List<String> {
        if (r.level == "info") return listOf("No warning signs matched, but no checker catches everything. If it asks for money, codes or " +
            "personal details, contact the company or person yourself using a number you already know.")
        val t = r.types.toSet()
        val out = mutableListOf("Don't reply, don't click links, and don't call any number in the message.")
        if (t.any { it in setOf("family_emergency", "new_number") }) out += "Call your family member on the number you already have for them. Use your family code word."
        if (t.any { it in setOf("bank_fraud_dept", "move_money_safe", "codes", "account_threat") }) out += "Call your bank using the number on the back of your card."
        if ("gov_threat" in t) out += "Government agencies don't threaten arrest by phone, text or email. Hang up."
        if (t.any { it in setOf("remote_access", "tech_support") }) out += "If you already let them into your computer, unplug it from the internet and have it checked."
        if ("recovery_scam" in t) out += "Real help after a scam is free: ic3.gov and reportfraud.ftc.gov."
        out += "If you already sent money: call your bank or payment app right away, then report it (tap Report a call)."
        return out
    }

    companion object {
        private val ADDR = Regex("\\b(0x[0-9a-fA-F]{40}|bc1[02-9ac-hj-np-z]{11,71}|ltc1[02-9ac-hj-np-z]{11,71}|(?:bitcoincash:)?[qp][02-9ac-hj-np-z]{41}|[EU]Q[A-Za-z0-9_-]{46}|T[1-9A-HJ-NP-Za-km-z]{33}|[13LMD][1-9A-HJ-NP-Za-km-z]{25,34}|r[1-9A-HJ-NP-Za-km-z]{24,34}|[1-9A-HJ-NP-Za-km-z]{32,44})\\b")
        fun addresses(s: String) = ADDR.findAll(s).map { it.value }.filter { it.any(Char::isDigit) && it.any(Char::isLetter) }.toList()
        fun norm(a0: String): String {
            var a = a0.trim()
            if (a.lowercase().startsWith("bitcoincash:")) a = a.substringAfter(":")
            return if (a.lowercase().startsWith("0x") || Regex("^[qp][02-9ac-hj-np-z]{41}$", RegexOption.IGNORE_CASE).matches(a)) a.lowercase() else a
        }
    }
}

internal fun JSONArray.objs() = (0 until length()).map { getJSONObject(it) }
internal fun JSONArray.strs() = (0 until length()).map { getString(it) }
internal fun JSONObject.toMap(): Map<String, String> = keys().asSequence().associateWith { getString(it) }
