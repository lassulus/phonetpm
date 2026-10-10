package dev.phonetpm.app

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import org.json.JSONArray
import org.json.JSONObject

enum class Outcome(val label: String) {
    Approved("Approved"),
    Denied("Denied"),
    TimedOut("Timed out"),
    Failed("Failed"),
}

data class HistoryEntry(
    val at: Long,
    val hostName: String,
    /** "SSH signature" or "age decrypt". */
    val action: String,
    val keyLabel: String,
    val description: String?,
    val outcome: Outcome,
)

/** Decided signing/decryption requests, newest first, capped at [MAX]. */
class RequestHistory(ctx: Context) {
    private val prefs = ctx.getSharedPreferences("history", Context.MODE_PRIVATE)
    private val state = MutableStateFlow(load())
    val all: StateFlow<List<HistoryEntry>> = state

    @Synchronized
    fun record(entry: HistoryEntry) {
        save((listOf(entry) + state.value).take(MAX))
    }

    @Synchronized
    fun clear() {
        save(emptyList())
    }

    private fun save(entries: List<HistoryEntry>) {
        val arr = JSONArray()
        for (e in entries) {
            arr.put(
                JSONObject()
                    .put("at", e.at)
                    .put("hostName", e.hostName)
                    .put("action", e.action)
                    .put("keyLabel", e.keyLabel)
                    .put("description", e.description ?: JSONObject.NULL)
                    .put("outcome", e.outcome.name)
            )
        }
        prefs.edit().putString(KEY, arr.toString()).apply()
        state.value = entries
    }

    private fun load(): List<HistoryEntry> {
        val raw = prefs.getString(KEY, null) ?: return emptyList()
        val arr = JSONArray(raw)
        return List(arr.length()) { i ->
            val o = arr.getJSONObject(i)
            HistoryEntry(
                at = o.getLong("at"),
                hostName = o.getString("hostName"),
                action = o.getString("action"),
                keyLabel = o.getString("keyLabel"),
                description = if (o.isNull("description")) null else o.getString("description"),
                outcome = Outcome.valueOf(o.getString("outcome")),
            )
        }
    }

    private companion object {
        const val KEY = "history"
        const val MAX = 100
    }
}
