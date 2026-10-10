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
    /** Paired host name, or the name the peer claims while pairing. */
    val hostName: String,
    val request: Request,
    /** Label of the requested key; `null` for pairing or an unknown key. */
    val keyLabel: String?,
) {
    internal val future = CompletableFuture<Response>()

    /** "SSH signature" / "age decrypt" for key operations, else `null`. */
    val action: String?
        get() = when (request) {
            is Request.Sign -> "SSH signature"
            is Request.Ecdh -> "age decrypt"
            else -> null
        }

    /** Free text the requester attached (only unlock requests carry one). */
    val description: String?
        get() = (request as? Request.Ecdh)?.description
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
    private val _queue = MutableStateFlow<List<PendingRequest>>(emptyList())
    val queue: StateFlow<List<PendingRequest>> = _queue

    /** True while [ApprovalActivity] is resumed; then no notification is needed. */
    @Volatile
    var activityVisible: Boolean = false

    /** Blocks the calling (Rust worker) thread until the user answers or the request times out. */
    fun submit(ctx: Context, peerId: String, hostName: String, request: Request): Response {
        val app = App.of(ctx)
        val keyId = when (request) {
            is Request.Sign -> request.keyId
            is Request.Ecdh -> request.keyId
            else -> null
        }
        val keyLabel = keyId?.let { app.keys.find(it)?.label ?: it }
        val pending = PendingRequest(seq.incrementAndGet(), peerId, hostName, request, keyLabel)
        _queue.update { it + pending }
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
        record(app, pending, if (timedOut) Outcome.TimedOut else outcomeOf(response))
        return response
    }

    private fun outcomeOf(response: Response): Outcome = when (response) {
        is Response.Signature, is Response.SharedSecret -> Outcome.Approved
        Response.Denied -> Outcome.Denied
        else -> Outcome.Failed
    }

    private fun record(app: App, pending: PendingRequest, outcome: Outcome) {
        val action = pending.action ?: return
        app.history.record(
            HistoryEntry(
                at = System.currentTimeMillis(),
                hostName = pending.hostName,
                action = action,
                keyLabel = pending.keyLabel.orEmpty(),
                description = pending.description,
                outcome = outcome,
            )
        )
    }

    fun complete(pending: PendingRequest, response: Response) {
        pending.future.complete(response)
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
        val text = when (pending.request) {
            is Request.Pair -> ctx.getString(R.string.notif_request_pair, pending.hostName)
            is Request.Sign -> ctx.getString(R.string.notif_request_sign, pending.keyLabel, pending.hostName)
            is Request.Ecdh -> ctx.getString(R.string.notif_request_ecdh, pending.keyLabel, pending.hostName)
            Request.ListKeys, Request.PushEndpoint -> return
        }
        val details = listOfNotNull(text, pending.description).joinToString("\n")
        // Background activity starts are blocked on modern Android; the
        // full-screen intent is what reliably brings the approval UI up.
        val notification = Notification.Builder(ctx, App.CHANNEL_REQUESTS)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(ctx.getString(R.string.notif_request_title))
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(details))
            .setCategory(Notification.CATEGORY_CALL)
            .setContentIntent(pi)
            .setFullScreenIntent(pi, true)
            .setOngoing(true)
            .setTimeoutAfter(TIMEOUT_SECONDS * 1000)
            .build()
        ctx.getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, notification)
        vibrate(ctx)
        try {
            ctx.startActivity(intent)
        } catch (_: Exception) {
            // Not allowed from the background; the notification covers it.
        }
    }
}
