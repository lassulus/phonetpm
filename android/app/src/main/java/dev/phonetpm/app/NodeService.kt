package dev.phonetpm.app

import android.app.ForegroundServiceStartNotAllowedException
import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.SystemClock
import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import uniffi.phonetpm_mobile.Node
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger

/**
 * Foreground service owning the iroh [Node]. Without UnifiedPush it runs
 * permanently; with it ([Push.onDemand]) it is started by a wake push and
 * stops itself after [IDLE_MS] without requests.
 */
class NodeService : Service() {
    private val executor = Executors.newSingleThreadExecutor()
    private var node: Node? = null
    private lateinit var connectivity: ConnectivityManager
    private val handler = Handler(Looper.getMainLooper())

    private val idleCheck = object : Runnable {
        override fun run() {
            val idle = SystemClock.elapsedRealtime() - lastActivity
            // A new host has no push endpoint yet: stay up while it may pair.
            val busy = inFlight.get() > 0 || PairingWindow.isOpen()
            if (App.of(this@NodeService).push.onDemand && !busy && idle >= IDLE_MS) {
                Log.i(TAG, "idle, stopping until the next wake push")
                stopSelf()
            } else {
                handler.postDelayed(this, IDLE_CHECK_MS)
            }
        }
    }

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) = networkChanged()
        override fun onLost(network: Network) = networkChanged()
        override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) = networkChanged()
    }

    override fun onCreate() {
        super.onCreate()
        val app = App.of(this)
        connectivity = getSystemService(ConnectivityManager::class.java)
        startForeground(
            NOTIFICATION_ID,
            notification(getString(R.string.notif_starting)),
            ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE,
        )
        executor.execute {
            try {
                val n = Node.start(app.identity.secretKey, NodeHandler(app))
                node = n
                _error.value = null
                _running.value = true
                val id = n.endpointId()
                getSystemService(NotificationManager::class.java)
                    .notify(NOTIFICATION_ID, notification(getString(R.string.notif_listening, id.take(8))))
                connectivity.registerDefaultNetworkCallback(networkCallback)
            } catch (e: Exception) {
                Log.e(TAG, "node start failed", e)
                _error.value = e.message ?: e.toString()
                stopSelf()
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopSelf()
            return START_NOT_STICKY
        }
        // Every start (e.g. another wake push) restarts the idle window.
        lastActivity = SystemClock.elapsedRealtime()
        handler.removeCallbacks(idleCheck)
        handler.postDelayed(idleCheck, IDLE_CHECK_MS)
        return if (App.of(this).push.onDemand) START_NOT_STICKY else START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        super.onDestroy()
        handler.removeCallbacks(idleCheck)
        _running.value = false
        executor.execute {
            node?.let { n ->
                try {
                    connectivity.unregisterNetworkCallback(networkCallback)
                } catch (_: IllegalArgumentException) {
                    // never registered
                }
                n.stop()
                n.destroy()
            }
            node = null
        }
        executor.shutdown()
    }

    private fun networkChanged() {
        executor.execute { node?.networkChanged() }
    }

    private fun notification(text: String): Notification {
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return Notification.Builder(this, App.CHANNEL_SERVICE)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(text)
            .setContentIntent(open)
            .setOngoing(true)
            .build()
    }

    companion object {
        private const val TAG = "NodeService"
        private const val NOTIFICATION_ID = 1
        private const val ACTION_STOP = "dev.phonetpm.app.STOP"
        /** On-demand mode: stop after this long without a request. */
        private const val IDLE_MS = 60_000L
        private const val IDLE_CHECK_MS = 10_000L

        private val _running = MutableStateFlow(false)
        val running: StateFlow<Boolean> = _running
        private val _error = MutableStateFlow<String?>(null)
        val error: StateFlow<String?> = _error

        @Volatile
        private var lastActivity = 0L
        private val inFlight = AtomicInteger()

        /** Runs a host request; the service does not idle-stop meanwhile. */
        fun <T> busy(block: () -> T): T {
            inFlight.incrementAndGet()
            lastActivity = SystemClock.elapsedRealtime()
            try {
                return block()
            } finally {
                lastActivity = SystemClock.elapsedRealtime()
                inFlight.decrementAndGet()
            }
        }

        fun start(ctx: Context) {
            try {
                ctx.startForegroundService(Intent(ctx, NodeService::class.java))
            } catch (e: ForegroundServiceStartNotAllowedException) {
                // Background start outside an allowed window (see PushServiceImpl).
                Log.e(TAG, "not allowed to start the service now", e)
                _error.value = e.message ?: e.toString()
            }
        }

        fun stop(ctx: Context) {
            ctx.startService(Intent(ctx, NodeService::class.java).setAction(ACTION_STOP))
        }
    }
}
