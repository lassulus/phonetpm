package dev.phonetpm.app

import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
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
) {
    internal val future = CompletableFuture<Response>()
}

/**
 * Bridges the Rust handler thread (which must block until the user decides)
 * and [ApprovalActivity] (which drains [queue] head-first). A request that is
 * not decided within [TIMEOUT_SECONDS] resolves to [Response.Denied].
 */
object RequestBroker {
    private const val TIMEOUT_SECONDS = 60L
    const val NOTIFICATION_ID = 2

    private val seq = AtomicLong()
    private val _queue = MutableStateFlow<List<PendingRequest>>(emptyList())
    val queue: StateFlow<List<PendingRequest>> = _queue

    /** True while [ApprovalActivity] is resumed; then no notification is needed. */
    @Volatile
    var activityVisible: Boolean = false

    /** Blocks the calling (Rust worker) thread until the user answers or the request times out. */
    fun submit(ctx: Context, peerId: String, hostName: String, request: Request): Response {
        val pending = PendingRequest(seq.incrementAndGet(), peerId, hostName, request)
        _queue.update { it + pending }
        present(ctx, pending)
        return try {
            pending.future.get(TIMEOUT_SECONDS, TimeUnit.SECONDS)
        } catch (_: TimeoutException) {
            Response.Denied
        } catch (_: InterruptedException) {
            Response.Denied
        } finally {
            pending.future.complete(Response.Denied) // no-op if already decided
            _queue.update { it - pending }
            if (_queue.value.isEmpty()) dismissNotification(ctx)
        }
    }

    fun complete(pending: PendingRequest, response: Response) {
        pending.future.complete(response)
    }

    fun dismissNotification(ctx: Context) {
        ctx.getSystemService(NotificationManager::class.java).cancel(NOTIFICATION_ID)
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
            is Request.Sign -> ctx.getString(R.string.notif_request_sign, pending.hostName)
            is Request.Ecdh -> ctx.getString(R.string.notif_request_ecdh, pending.hostName)
            Request.ListKeys, Request.PushEndpoint -> return
        }
        // Background activity starts are blocked on modern Android; the
        // full-screen intent is what reliably brings the approval UI up.
        val notification = Notification.Builder(ctx, App.CHANNEL_REQUESTS)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(ctx.getString(R.string.notif_request_title))
            .setContentText(text)
            .setCategory(Notification.CATEGORY_CALL)
            .setContentIntent(pi)
            .setFullScreenIntent(pi, true)
            .setOngoing(true)
            .setTimeoutAfter(TIMEOUT_SECONDS * 1000)
            .build()
        ctx.getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, notification)
        try {
            ctx.startActivity(intent)
        } catch (_: Exception) {
            // Not allowed from the background; the notification covers it.
        }
    }
}
