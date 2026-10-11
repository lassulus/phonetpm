package dev.phonetpm.app

/** Longest host name or key label shown, in code points (as `proto::MAX_NAME_CHARS`). */
const val MAX_NAME_CHARS = 64

/** Longest request description shown, in code points (as `proto::MAX_DESCRIPTION_CHARS`). */
const val MAX_DESCRIPTION_CHARS = 200

/**
 * Makes peer-supplied text safe to display, with the rules of the Rust
 * `proto::sanitize_text`: drops control (Cc) and format (Cf: bidi overrides
 * and isolates, zero-width characters, ...) characters, collapses whitespace
 * runs (including newlines) to one space, trims, and truncates to [maxChars]
 * code points, ending in '…' when truncated. The phone applies it on its own
 * and never relies on the host having done so.
 */
fun sanitizeText(s: String, maxChars: Int): String {
    val out = StringBuilder()
    var pendingSpace = false
    var i = 0
    while (i < s.length) {
        val cp = s.codePointAt(i)
        i += Character.charCount(cp)
        when {
            isWhiteSpace(cp) -> pendingSpace = out.isNotEmpty()
            Character.getType(cp).let { it == Character.CONTROL.toInt() || it == Character.FORMAT.toInt() } -> Unit
            else -> {
                if (pendingSpace) {
                    out.append(' ')
                    pendingSpace = false
                }
                out.appendCodePoint(cp)
            }
        }
    }
    val text = out.toString()
    if (text.codePointCount(0, text.length) <= maxChars) return text
    val end = text.offsetByCodePoints(0, (maxChars - 1).coerceAtLeast(0))
    return text.substring(0, end).trimEnd(' ') + '…'
}

/** Unicode White_Space, as Rust's `char::is_whitespace` (Java's own definitions differ). */
private fun isWhiteSpace(cp: Int): Boolean = cp in 0x09..0x0D || cp == 0x85 || Character.isSpaceChar(cp)

/** How a host appears wherever the user decides about it: `<name> (<first 8 of peer id>)`. */
fun hostLabel(hostName: String, peerId: String): String =
    "${sanitizeText(hostName, MAX_NAME_CHARS)} (${peerId.take(8)})"
