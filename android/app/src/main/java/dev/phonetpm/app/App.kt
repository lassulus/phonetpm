package dev.phonetpm.app

import android.app.Application
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
    lateinit var history: RequestHistory
        private set

    override fun onCreate() {
        super.onCreate()
        Native.nativeInit(applicationContext)
        identity = Identity(this)
        hosts = PairedHosts(this)
        keys = KeyStoreRepo(this)
        push = Push(this)
        history = RequestHistory(this)
        createChannels()
        push.refresh()
    }

    private fun createChannels() {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_SERVICE, getString(R.string.channel_service), NotificationManager.IMPORTANCE_LOW)
        )
        // Channel settings are frozen once created, so vibration and then the
        // removal of public lock-screen visibility each needed a new id.
        LEGACY_CHANNELS_REQUESTS.forEach(nm::deleteNotificationChannel)
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_REQUESTS, getString(R.string.channel_requests), NotificationManager.IMPORTANCE_HIGH)
                .apply {
                    enableVibration(true)
                    vibrationPattern = longArrayOf(0, 400, 200, 400)
                }
        )
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_PAIRING, getString(R.string.channel_pairing), NotificationManager.IMPORTANCE_HIGH)
                .apply {
                    enableVibration(false)
                    setSound(null, null)
                }
        )
    }

    companion object {
        const val CHANNEL_SERVICE = "service"
        const val CHANNEL_REQUESTS = "requests_private"
        const val CHANNEL_PAIRING = "pairing"
        private val LEGACY_CHANNELS_REQUESTS = listOf("requests", "requests_alert")

        fun of(ctx: Context): App = ctx.applicationContext as App
    }
}
