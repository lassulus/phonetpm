package dev.phonetpm.app

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import uniffi.phonetpm_mobile.Request
import uniffi.phonetpm_mobile.Response
import java.security.PrivateKey
import java.security.Signature
import javax.crypto.KeyAgreement

/**
 * Full-screen approval UI. Drains [RequestBroker.queue] one request at a time:
 * pairing shows Approve/Deny (Approve asks for a biometric or the device
 * credential), signing and ECDH go straight to a BiometricPrompt.
 */
class ApprovalActivity : FragmentActivity() {
    private val app by lazy { App.of(this) }

    /**
     * One authentication in flight, identifying which request a result
     * belongs to. [generation] is unique per authentication of this instance.
     */
    private class Auth(
        val generation: Long,
        val pending: PendingRequest,
        val privateKey: PrivateKey?,
        val signature: Signature?,
    ) {
        /** Set once [BiometricPrompt.cancelAuthentication] was called for it. */
        var cancelled = false
    }

    /**
     * androidx shares one callback slot per activity and looks it up only when
     * a result is delivered, so there is exactly one prompt and one callback,
     * and at most one authentication at a time: a result always belongs to
     * [active]. The next authentication starts only once the previous one has
     * reported back (a cancelled one reports an error) or, failing that, its
     * cancellation watchdog gave up on it. A callback while no authentication
     * of this instance is in flight is ignored.
     */
    private lateinit var prompt: BiometricPrompt
    private var active: Auth? = null
    private var generation = 0L

    /** The request on screen; read live so callbacks never act on a stale head. */
    private val head: PendingRequest?
        get() = RequestBroker.queue.value.firstOrNull()

    private val callback = object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
            val auth = takeActive() ?: return
            // A cancelled pairing prompt leaves the request up for another try.
            if (auth.pending.request !is Request.Pair) RequestBroker.complete(auth.pending, Response.Denied)
            advance()
        }

        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
            val auth = takeActive() ?: return
            if (!auth.pending.decided) {
                if (auth.pending.request is Request.Pair) {
                    app.hosts.add(auth.pending.peerId, auth.pending.hostName)
                    RequestBroker.complete(auth.pending, Response.Paired(app.push.endpoint))
                    PairingWindow.close()
                } else {
                    RequestBroker.complete(auth.pending, finishCrypto(auth, result))
                }
            }
            advance()
        }
    }

    /** Ends the authentication in flight, if any, and returns it. */
    private fun takeActive(): Auth? = active?.also { active = null }

    private companion object {
        /** How long a cancelled authentication may take to report back before it is abandoned. */
        const val CANCEL_GRACE_MS = 3_000L
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setShowWhenLocked(true)
        setTurnScreenOn(true)
        prompt = BiometricPrompt(this, ContextCompat.getMainExecutor(this), callback)

        setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                val queue by RequestBroker.queue.collectAsStateWithLifecycle()
                val hosts by app.hosts.all.collectAsStateWithLifecycle()
                val pending = queue.firstOrNull()
                Surface(modifier = Modifier.fillMaxSize()) {
                    ApprovalScreen(
                        pending = pending,
                        nameTaken = pending != null && pending.request is Request.Pair &&
                            hosts.any { sanitizeText(it.hostName, MAX_NAME_CHARS) == pending.hostName },
                        onApprove = ::authenticatePair,
                        onDeny = { RequestBroker.complete(it, Response.Denied) },
                    )
                }
            }
        }

        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.RESUMED) {
                RequestBroker.queue.map { it.firstOrNull() }.distinctUntilChanged().collect { advance() }
            }
        }
        // Also while in the background: an emptied queue still finishes the activity.
        lifecycleScope.launch {
            RequestBroker.queue.collect { if (it.isEmpty()) advance() }
        }
    }

    override fun onResume() {
        super.onResume()
        // The request notification stays until RequestBroker.submit resolves the
        // request: cancelling it here (the activity is often launched right after
        // it is posted) would silence its sound and vibration.
        RequestBroker.activityVisible = true
    }

    override fun onPause() {
        RequestBroker.activityVisible = false
        super.onPause()
    }

    override fun onDestroy() {
        // Configuration changes are handled in place (see the manifest), so
        // this instance is really going away.
        if (active != null) prompt.cancelAuthentication()
        super.onDestroy()
    }

    /**
     * Moves on to the queue head once no authentication for another request
     * is in flight. A prompt only starts while resumed: androidx silently
     * drops one started after the state was saved, and the RESUMED collector
     * calls this again on return.
     */
    private fun advance() {
        val h = head
        val auth = active
        if (auth != null) {
            // Its callback (or the watchdog) calls advance() again.
            if (auth.pending !== h || auth.pending.decided) cancel(auth)
            return
        }
        when {
            h == null -> finish()
            !lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED) -> Unit
            h.decided -> Unit // leaves the queue shortly
            h.request is Request.Sign || h.request is Request.Ecdh -> authenticateCrypto(h)
            else -> Unit // Pair waits for the Approve tap
        }
    }

    /**
     * Cancels [auth]. Its callback normally follows; if none arrives within
     * [CANCEL_GRACE_MS] (no prompt was actually shown, or androidx lost it),
     * it is abandoned so the queue does not wedge.
     */
    private fun cancel(auth: Auth) {
        if (auth.cancelled) return
        auth.cancelled = true
        prompt.cancelAuthentication()
        lifecycleScope.launch {
            delay(CANCEL_GRACE_MS)
            if (active?.generation == auth.generation) {
                active = null
                advance()
            }
        }
    }

    private fun authenticatePair(pending: PendingRequest) {
        if (active != null || pending !== head || pending.decided) return
        if (!lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) return
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Pair new host")
            .setSubtitle(pending.host)
            .setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
            .setConfirmationRequired(true)
            .build()
        authenticate(Auth(++generation, pending, null, null), info)
    }

    private fun authenticateCrypto(pending: PendingRequest) {
        val keyId = when (val r = pending.request) {
            is Request.Sign -> r.keyId
            is Request.Ecdh -> r.keyId
            else -> return
        }
        val privateKey = app.keys.find(keyId)?.let { app.keys.privateKey(it.id) }
        if (privateKey == null) {
            RequestBroker.complete(pending, Response.UnknownKey)
            return
        }
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(pending.action)
            .setSubtitle("Key ${pending.keyLabel} — ${pending.host}")
            .apply { pending.description?.let { setDescription("Description from host: $it") } }
            .setNegativeButtonText("Cancel")
            .setAllowedAuthenticators(BIOMETRIC_STRONG)
            // Passive modalities (face) must not approve without a tap.
            .setConfirmationRequired(true)
            .build()
        try {
            val signature = (pending.request as? Request.Sign)?.let {
                Signature.getInstance("SHA256withECDSA").apply { initSign(privateKey) }
            }
            authenticate(Auth(++generation, pending, privateKey, signature), info)
        } catch (e: Exception) {
            RequestBroker.complete(pending, Response.Error(e.message ?: e.toString()))
        }
    }

    private fun authenticate(auth: Auth, info: BiometricPrompt.PromptInfo) {
        active = auth
        try {
            if (auth.signature != null) {
                prompt.authenticate(info, BiometricPrompt.CryptoObject(auth.signature))
            } else {
                prompt.authenticate(info)
            }
        } catch (e: Exception) {
            active = null
            RequestBroker.complete(auth.pending, Response.Error(e.message ?: e.toString()))
        }
    }

    private fun finishCrypto(auth: Auth, result: BiometricPrompt.AuthenticationResult): Response {
        // Removed while the prompt was up.
        if (!app.hosts.isPaired(auth.pending.peerId)) return Response.Denied
        return try {
            when (val r = auth.pending.request) {
                is Request.Sign -> {
                    // Only the Signature unlocked for this very request may sign.
                    val sig = result.cryptoObject?.signature
                    if (sig == null || sig !== auth.signature) {
                        Response.Denied
                    } else {
                        sig.update(r.data)
                        Response.Signature(sig.sign())
                    }
                }
                is Request.Ecdh -> {
                    val peer = app.keys.ecdhPeerKey(r.keyId, r.peerPublicKey)
                    if (peer == null) {
                        Response.Error("peer key is not an uncompressed P-256 point on the curve")
                    } else {
                        val ka = KeyAgreement.getInstance("ECDH", KeyStoreRepo.ANDROID_KEYSTORE)
                        ka.init(auth.privateKey)
                        ka.doPhase(peer, true)
                        Response.SharedSecret(ka.generateSecret())
                    }
                }
                else -> Response.Denied
            }
        } catch (e: Exception) {
            Response.Error(e.message ?: e.toString())
        }
    }
}

@Composable
private fun ApprovalScreen(
    pending: PendingRequest?,
    /** True if a different, already paired host has the name this Pair claims. */
    nameTaken: Boolean,
    onApprove: (PendingRequest) -> Unit,
    onDeny: (PendingRequest) -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        if (pending == null) return@Column
        when (pending.request) {
            is Request.Pair -> {
                Text("Pair new host?", style = MaterialTheme.typography.headlineSmall)
                Spacer(Modifier.height(16.dp))
                Text(pending.hostName, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                if (nameTaken) {
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "A different host is already paired under this name. " +
                            "Deny unless you expect a second host called that.",
                        color = MaterialTheme.colorScheme.error,
                        textAlign = TextAlign.Center,
                    )
                }
                Spacer(Modifier.height(24.dp))
                Text("Host id", style = MaterialTheme.typography.labelMedium)
                Text(
                    pending.peerId.take(8),
                    fontFamily = FontFamily.Monospace,
                    fontSize = 40.sp,
                    fontWeight = FontWeight.Bold,
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    pending.peerId.chunked(4).joinToString(" "),
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodyMedium,
                    textAlign = TextAlign.Center,
                )
                Spacer(Modifier.height(16.dp))
                Text(
                    "Compare it with the \"this host:\" line printed by phonetpm pair. " +
                        "Approve only if they match.",
                    style = MaterialTheme.typography.bodyMedium,
                    textAlign = TextAlign.Center,
                )
                Spacer(Modifier.height(32.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                    OutlinedButton(onClick = { onDeny(pending) }) { Text("Deny") }
                    Button(onClick = { onApprove(pending) }) { Text("Approve") }
                }
            }
            is Request.Sign, is Request.Ecdh -> {
                Text(pending.action, style = MaterialTheme.typography.headlineSmall)
                Spacer(Modifier.height(8.dp))
                Text(pending.host, style = MaterialTheme.typography.bodyLarge)
                Spacer(Modifier.height(16.dp))
                Text("Key", style = MaterialTheme.typography.labelMedium)
                Text(pending.keyLabel.orEmpty(), style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                pending.description?.let {
                    Spacer(Modifier.height(16.dp))
                    Text("Description from host", style = MaterialTheme.typography.labelMedium)
                    Text(it, style = MaterialTheme.typography.bodyLarge, textAlign = TextAlign.Center)
                }
                Spacer(Modifier.height(24.dp))
                CircularProgressIndicator()
                Spacer(Modifier.height(24.dp))
                OutlinedButton(onClick = { onDeny(pending) }, modifier = Modifier.fillMaxWidth()) { Text("Deny") }
            }
            Request.ListKeys, Request.PushEndpoint -> Unit
        }
    }
}
