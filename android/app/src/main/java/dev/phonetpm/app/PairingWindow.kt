package dev.phonetpm.app

import android.os.SystemClock
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * The window the user opens in the Hosts tab to pair a new host. Pair
 * requests outside it are denied without any UI (see [RequestBroker.submit]).
 * A peer whose Pair was refused (denied or timed out) is not shown again
 * until the window is reopened, and [MAX_REFUSALS] refusals close it.
 * In memory only: it never survives the process.
 */
object PairingWindow {
    private const val DURATION_MS = 2 * 60_000L
    private const val MAX_REFUSALS = 3

    private val _closesAt = MutableStateFlow<Long?>(null)

    /** Guards [refused] and [refusals] together with changes of [closesAt]. */
    private val lock = Any()
    /** Peers refused during the current window. */
    private val refused = HashSet<String>()
    private var refusals = 0

    /** [SystemClock.elapsedRealtime] at which the window closes; `null` once closed. */
    val closesAt: StateFlow<Long?> = _closesAt

    fun open() = synchronized(lock) {
        refused.clear()
        refusals = 0
        _closesAt.value = SystemClock.elapsedRealtime() + DURATION_MS
    }

    fun isOpen(): Boolean = remainingMs() > 0

    fun remainingMs(): Long =
        _closesAt.value?.let { (it - SystemClock.elapsedRealtime()).coerceAtLeast(0) } ?: 0

    /**
     * The open window a Pair from [peerId] may be shown in, as its [closesAt]
     * value; `null` if the window is closed or this peer was already refused in it.
     */
    fun admit(peerId: String): Long? = synchronized(lock) {
        _closesAt.value?.takeIf { isOpen() && peerId !in refused }
    }

    /**
     * Records that a Pair from [peerId], admitted into [window] (see [admit]),
     * was denied or timed out. Ignored once that window is over; closes it
     * after [MAX_REFUSALS] refusals.
     */
    fun refuse(peerId: String, window: Long) {
        val tooMany = synchronized(lock) {
            if (_closesAt.value != window) return
            refused += peerId
            ++refusals >= MAX_REFUSALS
        }
        if (tooMany) close()
    }

    /** Closes the window early and denies a pairing request still waiting for the user. */
    fun close() {
        synchronized(lock) {
            _closesAt.value = null
            refused.clear()
            refusals = 0
        }
        // Outside [lock]: RequestBroker holds its own lock while calling [admit].
        RequestBroker.denyPairing()
    }
}
