package dev.phonetpm.app

import android.app.Application
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context

class App : Application() {
    lateinit var identity: Identity
        private set
    lateinit var hosts: PairedHosts
        private set
    lateinit var keys: KeyStoreRepo
        private set
    lateinit var push: Push
        private set

    override fun onCreate() {
        super.onCreate()
        Native.nativeInit(applicationContext)
        identity = Identity(this)
        hosts = PairedHosts(this)
        keys = KeyStoreRepo(this)
        push = Push(this)
        createChannels()
        push.refresh()
    }

    private fun createChannels() {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_SERVICE, getString(R.string.channel_service), NotificationManager.IMPORTANCE_LOW)
        )
        // Channel settings are frozen once created, so vibration needed a new id.
        nm.deleteNotificationChannel(LEGACY_CHANNEL_REQUESTS)
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_REQUESTS, getString(R.string.channel_requests), NotificationManager.IMPORTANCE_HIGH)
                .apply {
                    enableVibration(true)
                    vibrationPattern = longArrayOf(0, 400, 200, 400)
                    lockscreenVisibility = Notification.VISIBILITY_PUBLIC
                }
        )
    }

    companion object {
        const val CHANNEL_SERVICE = "service"
        const val CHANNEL_REQUESTS = "requests_alert"
        private const val LEGACY_CHANNEL_REQUESTS = "requests"

        fun of(ctx: Context): App = ctx.applicationContext as App
    }
}
