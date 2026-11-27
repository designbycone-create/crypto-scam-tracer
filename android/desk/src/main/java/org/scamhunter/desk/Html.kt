package org.scamhunter.desk

import java.net.URLDecoder
import java.util.Base64

/** Small pieces of HTML the app adds around the Desk's own pages (pure functions: unit-tested on the JVM). */
object Html {
    const val HOST = "desk.scamhunter.invalid"      // never resolves: every request to it is answered by the app itself
    const val BASE = "https://$HOST"

    /**
     * Added to every Desk page: WebView can't see the body of a form POST, so posting forms are turned into
     * a request the app can read (?__shpost=<base64 of the form>) and sent on to the Desk as a real POST.
     */
    const val SCRIPT = """<script>(function(){if(window.__shtd)return;window.__shtd=1;
function b64(s){return btoa(unescape(encodeURIComponent(s)));}
function go(f,btn){var fd=new FormData(f);if(btn&&btn.name)fd.append(btn.name,btn.value);
var u=new URL(f.getAttribute('action')||location.href,location.href);u.searchParams.delete('__shpost');
u.searchParams.set('__shpost',b64(new URLSearchParams(fd).toString()));location.href=u.toString();}
document.addEventListener('submit',function(e){var f=e.target;if((f.getAttribute('method')||'').toLowerCase()!=='post')return;
e.preventDefault();go(f,e.submitter);},true);
var orig=HTMLFormElement.prototype.submit;HTMLFormElement.prototype.submit=function(){
if((this.getAttribute('method')||'').toLowerCase()==='post'){go(this,null);}else{orig.call(this);}};})();</script>"""

    /** "/lookup?show=1&__shpost=..." -> ("/lookup?show=1", form body) or (path, null). */
    fun splitPost(path: String): Pair<String, ByteArray?> {
        val q = path.indexOf('?')
        if (q < 0) return Pair(path, null)
        val parts = path.substring(q + 1).split('&')
        val keep = ArrayList<String>()
        var body: ByteArray? = null
        for (part in parts) {
            if (part.startsWith("__shpost=")) {
                body = try {
                    Base64.getDecoder().decode(URLDecoder.decode(part.substring(9), "UTF-8"))
                } catch (e: Exception) { null }
            } else if (part.isNotEmpty()) keep.add(part)
        }
        val base = path.substring(0, q)
        return Pair(if (keep.isEmpty()) base else base + "?" + keep.joinToString("&"), body)
    }

    private val SAFE = Regex("[A-Za-z0-9/?=&._%~+-]*")

    fun inject(html: ByteArray): ByteArray {
        val s = String(html, Charsets.UTF_8)
        val i = s.lastIndexOf("</body>", ignoreCase = true)
        return (if (i >= 0) s.substring(0, i) + SCRIPT + s.substring(i) else s + SCRIPT).toByteArray(Charsets.UTF_8)
    }

    private fun esc(s: String) = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")

    fun redirect(location: String): ByteArray {
        // only the Desk's own pages, and only plain characters, so nothing can break out of the script
        val target = if (location.startsWith("/") && !location.startsWith("//") && SAFE.matches(location)) location else "/"
        return ("<!doctype html><meta charset=utf-8><script>location.replace(\"$target\")</script>").toByteArray()
    }

    // Night Desk colors (design/redesign/DESK_REDESIGN.md); fonts come from the app's own assets
    private const val STYLE = "@font-face{font-family:A;src:url(/static/fonts/atkinson-hyperlegible-latin-400-normal.woff2)}" +
        "@font-face{font-family:A;font-weight:700;src:url(/static/fonts/atkinson-hyperlegible-latin-700-normal.woff2)}" +
        "body{background:#071018;color:#F7F8FB;font:18px/1.5 A,system-ui,sans-serif;padding:16px}" +
        "h1{font-size:28px;line-height:1.25}a.b{display:flex;align-items:center;justify-content:center;min-height:56px;background:#5EEAD4;" +
        "color:#062821;border-radius:12px;font-weight:700;text-decoration:none;margin-top:18px}.s{color:#D5DDEA;font-size:18px}"

    /** A friendly full page for when the Desk can't be reached. */
    fun problem(kind: String, detail: String): ByteArray {
        val (title, text) = when (kind) {
            "offline" -> "Your Desk is offline" to "The phone reached your Worker, but the Desk on your computer isn't connected. " +
                "Is the computer on, awake, and the Desk running?"
            "unpaired" -> "This phone isn't paired any more" to "The pairing was removed or replaced on the Desk. " +
                "Pair again: on the computer, Settings &rarr; Phone app &rarr; Pair my phone."
            "slow" -> "Too many requests" to "Wait a minute and try again."
            "timeout" -> "The Desk took too long to answer" to "The computer may be busy. Try again in a moment."
            "network" -> "No connection" to "This phone can't reach the internet right now."
            "crypto" -> "Couldn't open the Desk's answer" to "The answer failed its security check, so it wasn't shown. " +
                "If this keeps happening, pair the phone again."
            else -> "Something went wrong" to "Try again in a moment."
        }
        val repair = if (kind == "unpaired" || kind == "crypto") "<a class=b href='shtd://pair'>Pair again</a>" else ""
        return ("<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><style>$STYLE</style>" +
            "<h1>$title</h1><p>$text</p><a class=b href='javascript:location.reload()'>Try again</a>$repair" +
            "<p class=s>${esc(detail.take(160))}</p>").toByteArray(Charsets.UTF_8)
    }
}
