package dev.phonetpm.app

import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import org.json.JSONArray
import org.json.JSONObject

data class PairedHost(val peerId: String, val hostName: String, val pairedAt: Long)

/** Hosts allowed to talk to us, keyed by their authenticated iroh endpoint id. */
class PairedHosts(ctx: Context) {
    private val prefs = ctx.getSharedPreferences("hosts", Context.MODE_PRIVATE)
    private val state = MutableStateFlow(load())
    val all: StateFlow<List<PairedHost>> = state

    fun find(peerId: String): PairedHost? = state.value.firstOrNull { it.peerId == peerId }

    fun isPaired(peerId: String): Boolean = find(peerId) != null

    @Synchronized
    fun add(peerId: String, hostName: String) {
        val next = state.value.filterNot { it.peerId == peerId } +
            PairedHost(peerId, hostName, System.currentTimeMillis())
        save(next)
    }

    /** Local, display-only name change; the host is not told. */
    @Synchronized
    fun rename(peerId: String, hostName: String) {
        save(state.value.map { if (it.peerId == peerId) it.copy(hostName = hostName) else it })
    }

    @Synchronized
    fun remove(peerId: String) {
        save(state.value.filterNot { it.peerId == peerId })
    }

    private fun save(hosts: List<PairedHost>) {
        val arr = JSONArray()
        for (h in hosts) {
            arr.put(
                JSONObject()
                    .put("peerId", h.peerId)
                    .put("hostName", h.hostName)
                    .put("pairedAt", h.pairedAt)
            )
        }
        prefs.edit().putString(KEY, arr.toString()).apply()
        state.value = hosts
    }

    private fun load(): List<PairedHost> {
        val raw = prefs.getString(KEY, null) ?: return emptyList()
        val arr = JSONArray(raw)
        return List(arr.length()) { i ->
            val o = arr.getJSONObject(i)
            PairedHost(o.getString("peerId"), o.getString("hostName"), o.getLong("pairedAt"))
        }
    }

    private companion object {
        const val KEY = "hosts"
    }
}
