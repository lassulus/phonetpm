package dev.phonetpm.app

import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.media.AudioAttributes
import android.os.Build
import android.os.VibrationAttributes
import android.os.VibrationEffect
import android.os.VibratorManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import uniffi.phonetpm_mobile.Request
import uniffi.phonetpm_mobile.Response
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicLong

/** A request from a host that needs the user's decision on screen. */
class PendingRequest(
    val id: Long,
    val peerId: String,
    /** Sanitized paired host name, or the sanitized name the peer claims while pairing. */
    val hostName: String,
    val request: Request,
    /** Sanitized label of the requested key; `null` for pairing. */
    val keyLabel: String?,
) {
    internal val future = CompletableFuture<Response>()

    /** True once answered (by the user, a timeout, or a host removal). */
    val decided: Boolean
        get() = future.isDone

    /** The host as shown to the user: name plus short peer id. */
    val host: String = hostLabel(hostName, peerId)

    val action: String = when (request) {
        is Request.Pair -> "Pairing"
        is Request.Sign -> "SSH signature"
        is Request.Ecdh -> "age decrypt"
        Request.ListKeys, Request.PushEndpoint -> throw IllegalArgumentException("no user decision for $request")
    }

    /** Sanitized free text the requester attached, if any. */
    val description: String? = when (request) {
        is Request.Sign -> request.description
        is Request.Ecdh -> request.description
        else -> null
    }?.let { sanitizeText(it, MAX_DESCRIPTION_CHARS) }?.takeIf { it.isNotEmpty() }
}

/**
 * Bridges the Rust handler thread (which must block until the user decides)
 * and [ApprovalActivity] (which drains [queue] head-first). A request that is
 * not decided within [TIMEOUT_SECONDS] resolves to [Response.Denied].
 */
object RequestBroker {
    private const val TIMEOUT_SECONDS = 60L
    const val NOTIFICATION_ID = 2
    /** Repeats from index 0 until the request is resolved. */
    private val VIBRATION_PATTERN = longArrayOf(0, 500, 250, 500, 1200)

    private val seq = AtomicLong()
    /** Guards admission to [queue] against [denyWhere] sweeps. */
    private val lock = Any()
    private val _queue = MutableStateFlow<List<PendingRequest>>(emptyList())
    val queue: StateFlow<List<PendingRequest>> = _queue

    /** True while [ApprovalActivity] is resumed; then no notification is needed. */
    @Volatile
    var activityVisible: Boolean = false

    /**
     * Blocks the calling (Rust worker) thread until the user answers or the
     * request times out. A Pair is denied at once, without any UI, unless the
     * [PairingWindow] is open, no other Pair is waiting and this peer was not
     * refused in the window before. Only an admitted request counts as node
     * activity ([NodeService.busy]).
     */
    fun submit(ctx: Context, peerId: String, hostName: String, request: Request): Response {
        val app = App.of(ctx)
        val keyLabel = when (request) {
            is Request.Sign -> request.keyId
            is Request.Ecdh -> request.keyId
            else -> null
        }?.let { keyId -> sanitizeText(app.keys.find(keyId)?.label ?: keyId, MAX_NAME_CHARS) }
        val pending = PendingRequest(seq.incrementAndGet(), peerId, hostName, request, keyLabel)
        val window = synchronized(lock) {
            val w = if (request is Request.Pair) {
                PairingWindow.admit(peerId)
                    ?.takeIf { _queue.value.none { q -> q.request is Request.Pair } }
                    ?: return Response.Denied
            } else {
                null
            }
            _queue.update { it + pending }
            w
        }
        return NodeService.busy { await(ctx, app, pending, window) }
    }

    private fun await(ctx: Context, app: App, pending: PendingRequest, window: Long?): Response {
        present(ctx, pending)
        var timedOut = false
        val response = try {
            pending.future.get(TIMEOUT_SECONDS, TimeUnit.SECONDS)
        } catch (_: TimeoutException) {
            timedOut = true
            Response.Denied
        } catch (_: InterruptedException) {
            Response.Denied
        } finally {
            pending.future.complete(Response.Denied) // no-op if already decided
            _queue.update { it - pending }
            if (_queue.value.isEmpty()) clearAlert(ctx)
        }
        // A refused peer may not take the pairing slot again in this window.
        if (window != null && response !is Response.Paired) PairingWindow.refuse(pending.peerId, window)
        record(app, pending, if (timedOut) Outcome.TimedOut else outcomeOf(response))
        return response
    }

    private fun outcomeOf(response: Response): Outcome = when (response) {
        is Response.Paired, is Response.Signature, is Response.SharedSecret -> Outcome.Approved
        Response.Denied -> Outcome.Denied
        else -> Outcome.Failed
    }

    private fun record(app: App, pending: PendingRequest, outcome: Outcome) {
        app.history.record(
            HistoryEntry(
                at = System.currentTimeMillis(),
                hostName = pending.hostName,
                peerId = pending.peerId,
                action = pending.action,
                keyLabel = pending.keyLabel.orEmpty(),
                description = pending.description,
                outcome = outcome,
            )
        )
    }

    fun complete(pending: PendingRequest, response: Response) {
        pending.future.complete(response)
    }

    /** Denies every queued or in-flight request from [peerId], e.g. after the host was removed. */
    fun denyFrom(peerId: String) = denyWhere { it.peerId == peerId }

    /** Denies a pairing request still waiting for the user. */
    fun denyPairing() = denyWhere { it.request is Request.Pair }

    private fun denyWhere(predicate: (PendingRequest) -> Boolean) {
        synchronized(lock) {
            _queue.value.filter(predicate).forEach { complete(it, Response.Denied) }
        }
    }

    private fun clearAlert(ctx: Context) {
        ctx.getSystemService(NotificationManager::class.java).cancel(NOTIFICATION_ID)
        ctx.getSystemService(VibratorManager::class.java).defaultVibrator.cancel()
    }

    /**
     * Notification alerting alone proved unreliable (the screen turns on, but
     * nothing buzzes), so vibrate explicitly, call-style, until [clearAlert].
     * Alarm usage: the user started the operation, so it must reach them in a
     * pocket even with the ringer on silent.
     */
    private fun vibrate(ctx: Context) {
        val vibrator = ctx.getSystemService(VibratorManager::class.java).defaultVibrator
        val effect = VibrationEffect.createWaveform(VIBRATION_PATTERN, 0)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            vibrator.vibrate(effect, VibrationAttributes.createForUsage(VibrationAttributes.USAGE_ALARM))
        } else {
            @Suppress("DEPRECATION")
            vibrator.vibrate(effect, AudioAttributes.Builder().setUsage(AudioAttributes.USAGE_ALARM).build())
        }
    }

    private fun present(ctx: Context, pending: PendingRequest) {
        if (activityVisible) return
        val intent = Intent(ctx, ApprovalActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        val pi = PendingIntent.getActivity(
            ctx, 0, intent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        // Pairing happens while the user is at the phone (the pairing window
        // is open), so it gets a silent channel and never vibrates.
        val (channel, text) = when (pending.request) {
            is Request.Pair ->
                App.CHANNEL_PAIRING to ctx.getString(R.string.notif_request_pair, pending.host)
            is Request.Sign ->
                App.CHANNEL_REQUESTS to ctx.getString(R.string.notif_request_sign, pending.keyLabel, pending.host)
            is Request.Ecdh ->
                App.CHANNEL_REQUESTS to ctx.getString(R.string.notif_request_ecdh, pending.keyLabel, pending.host)
            Request.ListKeys, Request.PushEndpoint -> return
        }
        val details = listOfNotNull(
            text,
            pending.description?.let { ctx.getString(R.string.notif_request_description, it) },
        ).joinToString("\n")
        // On a secure lock screen only this generic version is shown.
        val publicVersion = Notification.Builder(ctx, channel)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(ctx.getString(R.string.notif_request_title))
            .build()
        // Background activity starts are blocked on modern Android; the
        // full-screen intent is what reliably brings the approval UI up.
        val notification = Notification.Builder(ctx, channel)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(ctx.getString(R.string.notif_request_title))
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(details))
            .setVisibility(Notification.VISIBILITY_PRIVATE)
            .setPublicVersion(publicVersion)
            .setCategory(Notification.CATEGORY_CALL)
            .setContentIntent(pi)
            .setFullScreenIntent(pi, true)
            .setOngoing(true)
            .setTimeoutAfter(TIMEOUT_SECONDS * 1000)
            .build()
        ctx.getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, notification)
        if (pending.request !is Request.Pair) vibrate(ctx)
        try {
            ctx.startActivity(intent)
        } catch (_: Exception) {
            // Not allowed from the background; the notification covers it.
        }
    }
}
