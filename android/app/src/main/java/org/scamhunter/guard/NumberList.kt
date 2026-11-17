package org.scamhunter.guard

import android.content.Context
import org.json.JSONObject
import java.io.File
import java.io.RandomAccessFile
import java.net.HttpURLConnection
import java.net.URL
import java.util.zip.GZIPInputStream

/**
 * FTC-reported scam / robocall numbers, kept on the phone. Incoming numbers are looked up here,
 * on the phone itself: your calls are never sent anywhere.
 *
 * The list is published once a day by the ScamHunter project (from the FTC's Do Not Call reported
 * calls data) and downloaded over the internet. It's stored as fixed-width sorted lines so a lookup
 * is a few file reads, fast enough for the 5 seconds Android allows a call screener.
 */
object NumberList {
    const val URL_LIST = "https://raw.githubusercontent.com/designbycone-create/crypto-scam-tracer/data/callers.json.gz"
    private const val W = 32                       // bytes per line: number,reports,robo,subject,age\n
    private const val FILE = "numbers.idx"
    private const val META = "numbers_meta.json"

    data class Hit(val number: String, val reports: Int, val robo: Int, val subject: String, val daysAgo: Int)
    data class Rating(val level: String, val headline: String, val subject: String?, val robocall: Boolean)

    private val FRAUD = Regex("imposter|impostor|government|social security|irs|medicare|bank|computer|tech|warranty|prize|" +
        "sweepstakes|lottery|debt|loan|grant|charit|crypto|investment|utility|police|family|kidnap|romance", RegexOption.IGNORE_CASE)

    fun norm(number: String?): String? {
        var d = (number ?: "").filter(Char::isDigit)
        if (d.length == 11 && d[0] == '1') d = d.substring(1)
        return if (d.length == 10 && d[0] in "23456789" && d[3] in "23456789") d else null
    }

    /** Same rating as the Desk (shield/callerlist.py): many recent reports, weighted by a fraud subject. */
    fun rate(h: Hit?, days: Int): Rating {
        if (h == null) return Rating("none", "No reports in the FTC list", null, false)
        val fraud = FRAUD.containsMatchIn(h.subject)
        var level = when { h.reports >= 10 -> "high"; h.reports >= 3 -> "medium"; else -> "low" }
        if (fraud && level == "medium") level = "high"
        val head = if (h.reports >= 3) "Reported ${h.reports} times in the last $days days" else "Reported once or twice in the last $days days"
        return Rating(level, head, h.subject.ifBlank { null }, h.robo * 2 >= h.reports)
    }

    fun meta(ctx: Context): JSONObject = try { JSONObject(File(ctx.filesDir, META).readText()) } catch (e: Exception) { JSONObject() }

    fun lookup(ctx: Context, number: String?): Hit? = lookupIn(ctx.filesDir, number)

    /** Lookup in a directory holding the index + meta (pure file code, so it's unit-tested on a computer). */
    fun lookupIn(dir: File, number: String?): Hit? {
        val n = norm(number) ?: return null
        val f = File(dir, FILE)
        if (!f.exists()) return null
        val subjects = try { JSONObject(File(dir, META).readText()).optJSONArray("s") } catch (e: Exception) { null }
        RandomAccessFile(f, "r").use { raf ->
            var lo = 0L
            var hi = raf.length() / W - 1
            val buf = ByteArray(W)
            while (lo <= hi) {
                val mid = (lo + hi) / 2
                raf.seek(mid * W); raf.readFully(buf)
                val line = String(buf, Charsets.US_ASCII)
                val c = line.substring(0, 10).compareTo(n)
                when {
                    c == 0 -> {
                        val p = line.trim().split(",")
                        val si = p[3].trim().toInt()
                        return Hit(n, p[1].trim().toInt(), p[2].trim().toInt(),
                            if (subjects != null && si < subjects.length()) subjects.getString(si) else "", p[4].trim().toInt())
                    }
                    c < 0 -> lo = mid + 1
                    else -> hi = mid - 1
                }
            }
        }
        return null
    }

    /** Converts the published list (JSON) into the lookup file. Returns how many numbers it holds. */
    fun install(ctx: Context, json: String): Int = installIn(ctx.filesDir, json)

    fun installIn(dir: File, json: String): Int {
        val j = JSONObject(json)
        val n = j.getJSONObject("n")
        val keys = n.keys().asSequence().filter { norm(it) == it }.sorted().toList()
        val tmp = File(dir, "$FILE.tmp")
        tmp.outputStream().buffered().use { out ->
            for (k in keys) {
                val a = n.getJSONArray(k)
                val line = String.format(java.util.Locale.ROOT, "%s,%5d,%5d,%4d,%3d", k, minOf(a.getInt(0), 99999), minOf(a.getInt(1), 99999),
                    minOf(a.getInt(2), 9999), minOf(a.getInt(3), 999)).padEnd(W - 1) + "\n"
                out.write(line.toByteArray(Charsets.US_ASCII))
            }
        }
        val dest = File(dir, FILE)
        dest.delete()
        if (!tmp.renameTo(dest)) throw RuntimeException("couldn't save the list")
        val meta = JSONObject().put("s", j.getJSONArray("s")).put("to", j.optString("to")).put("days", j.optInt("days"))
            .put("count", keys.size).put("updated", System.currentTimeMillis())
        File(dir, META).writeText(meta.toString())
        return keys.size
    }

    /** Downloads today's list. Runs off the main thread (from ListJob or the Settings screen). */
    fun download(ctx: Context): Int {
        val c = URL(URL_LIST).openConnection() as HttpURLConnection
        c.connectTimeout = 20000; c.readTimeout = 60000
        c.setRequestProperty("User-Agent", "ScamHunterGuard/0.1 (Android)")
        try {
            if (c.responseCode != 200) throw RuntimeException("list server answered ${c.responseCode}")
            val text = GZIPInputStream(c.inputStream).bufferedReader().use { it.readText() }
            return install(ctx, text)
        } finally { c.disconnect() }
    }
}
