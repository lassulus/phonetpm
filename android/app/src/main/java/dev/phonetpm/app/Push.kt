package dev.phonetpm.app

import android.app.Activity
import android.content.Context
import android.util.Log
import org.unifiedpush.android.connector.FailedReason
import org.unifiedpush.android.connector.PushService
import org.unifiedpush.android.connector.UnifiedPush
import org.unifiedpush.android.connector.data.PushEndpoint
import org.unifiedpush.android.connector.data.PushMessage

/**
 * UnifiedPush wake-up. With a distributor installed (e.g. ntfy) we have an
 * [endpoint]; paired hosts learn it and POST to it when they want to connect,
 * so [NodeService] runs only on demand. Without one, [endpoint] is null and
 * the service stays up permanently, as before.
 */
class Push(private val ctx: Context) {
    private val prefs = ctx.getSharedPreferences("push", Context.MODE_PRIVATE)

    /** Current UnifiedPush endpoint URL, null without a distributor. */
    var endpoint: String?
        get() = prefs.getString(KEY_ENDPOINT, null)
        private set(value) = prefs.edit().putString(KEY_ENDPOINT, value).apply()

    val onDemand: Boolean get() = endpoint != null

    /**
     * Picks the saved or default distributor and registers. Needs an activity:
     * the connector may show the distributor's link screen.
     */
    fun register(activity: Activity) {
        UnifiedPush.tryUseCurrentOrDefaultDistributor(activity) { ok ->
            if (ok) UnifiedPush.register(ctx) else lost()
        }
    }

    /** Re-registers with an already chosen distributor; call on every process start. */
    fun refresh() {
        if (UnifiedPush.getAckDistributor(ctx) != null) UnifiedPush.register(ctx) else lost()
    }

    internal fun update(url: String) {
        endpoint = url
    }

    /** Back to always-on: no distributor, or it dropped our registration. */
    internal fun lost() {
        if (endpoint == null) return
        endpoint = null
        if (App.of(ctx).identity.serviceEnabled) NodeService.start(ctx)
    }

    private companion object {
        const val KEY_ENDPOINT = "endpoint"
    }
}

/**
 * Receives UnifiedPush events. A message is just a wake-up: hosts send no
 * payload worth reading, so the content is ignored.
 *
 * Starting a foreground service from the background is forbidden since
 * Android 12 (ForegroundServiceStartNotAllowedException). The UnifiedPush
 * Android spec (AND_3) requires the distributor to raise the receiving app to
 * foreground importance for ~5 s per message: either via a temporary
 * power-allowlist (privileged distributors) or by binding the app's
 * RAISE_TO_FOREGROUND service, which the connector library declares in its
 * own manifest (internal.RaiseToForegroundService). Within that window
 * startForegroundService() is allowed, also on Android 14+, and the
 * connectedDevice type's prerequisite (CHANGE_NETWORK_STATE) is a normal
 * permission we already hold. So onMessage starts NodeService directly
 * instead of e.g. posting a notification the user would have to tap.
 */
class PushServiceImpl : PushService() {
    private val push get() = App.of(this).push

    override fun onNewEndpoint(endpoint: PushEndpoint, instance: String) {
        Log.i(TAG, "new push endpoint")
        push.update(endpoint.url)
    }

    override fun onMessage(message: PushMessage, instance: String) {
        if (!App.of(this).identity.serviceEnabled) return
        Log.i(TAG, "woken by push")
        NodeService.start(this)
    }

    override fun onRegistrationFailed(reason: FailedReason, instance: String) {
        Log.w(TAG, "push registration failed: $reason")
        push.lost()
    }

    override fun onUnregistered(instance: String) {
        Log.i(TAG, "push unregistered")
        push.lost()
    }

    private companion object {
        const val TAG = "Push"
    }
}
