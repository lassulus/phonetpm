package dev.phonetpm.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        val app = App.of(context)
        // With UnifiedPush the service starts when a host sends a wake push.
        if (app.identity.serviceEnabled && !app.push.onDemand) NodeService.start(context)
    }
}
