"""Inline SVG icons for the Night Desk look (design/redesign/DESK_REDESIGN.md). Each result level always shows its
word AND its icon: color is never the only signal."""

_P = {
    "stop": '<path fill="{c}" d="M8 2h8l6 6v8l-6 6H8l-6-6V8l6-6zm3 6h2v5h-2V8zm0 6h2v2h-2v-2z"/>',
    "careful": '<path fill="{c}" d="M12 3 2 20h20L12 3zm1 6v5h-2V9h2zm0 7v2h-2v-2h2z"/>',
    "ok": '<circle cx="12" cy="12" r="8" fill="none" stroke="{c}" stroke-width="2"/><circle cx="12" cy="12" r="3" fill="{c}"/>',
    "info": '<circle cx="12" cy="12" r="8" fill="none" stroke="{c}" stroke-width="2"/><rect x="11" y="10" width="2" height="6" fill="{c}"/>'
            '<rect x="11" y="7" width="2" height="2" fill="{c}"/>',
    "down": '<path fill="none" stroke="{c}" stroke-width="2" stroke-linecap="round" d="M10 14a4 4 0 0 1 0-5.6l2.2-2.2a4 4 0 0 1 5.6 5.6L16.5 13'
            'M14 10a4 4 0 0 1 0 5.6l-2.2 2.2a4 4 0 0 1-5.6-5.6L7.5 11M4 4l3 3M20 20l-3-3"/>',
    "clock": '<circle cx="12" cy="12" r="8.5" fill="none" stroke="{c}" stroke-width="2"/><path fill="none" stroke="{c}" stroke-width="2" '
             'stroke-linecap="round" d="M12 7.5V12l3 2"/>',
    "spark": '<path fill="{c}" d="M12 2l2.2 6.3L20.5 10.5l-6.3 2.2L12 19l-2.2-6.3L3.5 10.5l6.3-2.2z"/>',
    "shield": '<path fill="none" stroke="{c}" stroke-width="1.8" stroke-linejoin="round" d="M12 2.5l8 3v6c0 5-3.4 8.9-8 10.5-4.6-1.6-8-5.5-8-10.5v-6z"/>'
              '<circle cx="12" cy="11.5" r="3" fill="{c}"/>',
    "home": '<path fill="none" stroke="{c}" stroke-width="2" stroke-linejoin="round" d="M3 11.5 12 4l9 7.5M5.5 10v10h13V10"/>',
    "map": '<circle cx="12" cy="12" r="9" fill="none" stroke="{c}" stroke-width="2"/><path fill="none" stroke="{c}" stroke-width="2" '
           'd="M3 12h18M12 3c2.8 3 2.8 15 0 18M12 3c-2.8 3-2.8 15 0 18"/>',
    "crypto": '<rect x="3" y="6.5" width="18" height="12.5" rx="2.5" fill="none" stroke="{c}" stroke-width="2"/><path fill="none" stroke="{c}" '
              'stroke-width="2" d="M16 12.75h2M3 10h18"/>',
    "phone": '<rect x="7" y="2.5" width="10" height="19" rx="2.2" fill="none" stroke="{c}" stroke-width="2"/><path stroke="{c}" stroke-width="2" d="M11 18h2"/>',
    "defense": '<path fill="none" stroke="{c}" stroke-width="2" stroke-linejoin="round" d="M12 2.5l8 3v6c0 5-3.4 8.9-8 10.5-4.6-1.6-8-5.5-8-10.5v-6z"/>'
               '<path fill="none" stroke="{c}" stroke-width="2" d="m8.5 12 2.5 2.5 4.5-5"/>',
    "settings": '<circle cx="12" cy="12" r="3.2" fill="none" stroke="{c}" stroke-width="2"/><path fill="none" stroke="{c}" stroke-width="2" '
                'd="M12 2.5v3M12 18.5v3M2.5 12h3M18.5 12h3M5.3 5.3l2.1 2.1M16.6 16.6l2.1 2.1M5.3 18.7l2.1-2.1M16.6 7.4l2.1-2.1"/>',
}
INK = {"stop": "#FFD0D6", "careful": "#FFE3A3", "ok": "#C9F6EC", "info": "#D6E4FF", "down": "#E4F0FC",
       "clock": "#FFE3A3", "spark": "#FFE3A3", "shield": "#5EEAD4"}
WORD = {"stop": "STOP", "careful": "Be careful", "ok": "No red flags found", "info": "Info", "down": "Website is down"}
# the Desk's older pages call these levels stop / caution / ok / info
LEVEL = {"stop": "stop", "caution": "careful", "careful": "careful", "warn": "careful", "ok": "ok", "good": "ok", "info": "info", "down": "down"}


def svg(name, size=28, color=None, label=None):
    c = color or INK.get(name, "currentColor")
    a = f'role="img" aria-label="{label}"' if label else 'aria-hidden="true" focusable="false"'
    return f'<svg width="{size}" height="{size}" viewBox="0 0 24 24" {a}>{_P[name].format(c=c)}</svg>'


def chip(level, word=None):
    lv = LEVEL.get(level, "info")
    return f'<span class="chip {lv}">{svg(lv, 20)}{word or ("OK" if lv == "ok" else WORD[lv])}</span>'


def result(level, title=None, sentence="", why=(), actions="", extra=""):
    """A Night Desk result card: icon tile, the word, one sentence, a Why list, buttons."""
    import html
    lv = LEVEL.get(level, "info")
    why_html = ("<ul class=why>" + "".join(f"<li>{html.escape(w)}</li>" for w in why) + "</ul>") if why else ""
    return (f'<section class="result result-{lv}" aria-live="polite"><div class=badge-icon>{svg(lv, 32)}</div><div>'
            f'<h2>{html.escape(title or WORD[lv])}</h2>' + (f"<p>{html.escape(sentence)}</p>" if sentence else "")
            + why_html + extra + (f"<div class=actions>{actions}</div>" if actions else "") + "</div></section>")
