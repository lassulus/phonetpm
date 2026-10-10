package dev.phonetpm.app

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
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
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import uniffi.phonetpm_mobile.Request
import uniffi.phonetpm_mobile.Response
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import javax.crypto.KeyAgreement

/**
 * Full-screen approval UI. Drains [RequestBroker.queue] one request at a time:
 * pairing shows Approve/Deny, signing and ECDH go straight to a BiometricPrompt.
 */
class ApprovalActivity : FragmentActivity() {
    private val app by lazy { App.of(this) }
    private var prompted: PendingRequest? = null
    private var prompt: BiometricPrompt? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setShowWhenLocked(true)
        setTurnScreenOn(true)

        setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                val queue by RequestBroker.queue.collectAsStateWithLifecycle()
                Surface(modifier = Modifier.fillMaxSize()) {
                    ApprovalScreen(
                        pending = queue.firstOrNull(),
                        onApprove = ::approvePair,
                        onDeny = { RequestBroker.complete(it, Response.Denied) },
                    )
                }
            }
        }

        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.RESUMED) {
                RequestBroker.queue.map { it.firstOrNull() }.distinctUntilChanged().collect { head ->
                    if (prompted !== head) {
                        prompt?.cancelAuthentication()
                        prompt = null
                    }
                    when {
                        head == null -> finish()
                        head.request is Request.Pair -> Unit
                        prompted !== head -> showBiometric(head)
                    }
                }
            }
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
        prompt?.cancelAuthentication()
        super.onDestroy()
    }

    private fun approvePair(pending: PendingRequest) {
        val req = pending.request as? Request.Pair ?: return
        app.hosts.add(pending.peerId, req.hostName)
        RequestBroker.complete(pending, Response.Paired(app.push.endpoint))
    }

    private fun showBiometric(pending: PendingRequest) {
        prompt?.cancelAuthentication()
        prompted = pending
        val keyId = when (val r = pending.request) {
            is Request.Sign -> r.keyId
            is Request.Ecdh -> r.keyId
            else -> return
        }
        val meta = app.keys.find(keyId)
        val privateKey = meta?.let { app.keys.privateKey(it.id) }
        if (meta == null || privateKey == null) {
            RequestBroker.complete(pending, Response.UnknownKey)
            return
        }

        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                RequestBroker.complete(pending, Response.Denied)
            }

            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                RequestBroker.complete(pending, finishCrypto(pending, result, privateKey))
            }
        }
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(if (pending.request is Request.Sign) "SSH signature" else "age decrypt")
            .setSubtitle("${meta.label} — ${pending.hostName}")
            .setNegativeButtonText("Cancel")
            .setAllowedAuthenticators(BIOMETRIC_STRONG)
            .setConfirmationRequired(false)
            .build()
        val p = BiometricPrompt(this, ContextCompat.getMainExecutor(this), callback)
        prompt = p
        try {
            when (pending.request) {
                is Request.Sign -> {
                    val sig = Signature.getInstance("SHA256withECDSA").apply { initSign(privateKey) }
                    p.authenticate(info, BiometricPrompt.CryptoObject(sig))
                }
                else -> p.authenticate(info)
            }
        } catch (e: Exception) {
            RequestBroker.complete(pending, Response.Error(e.message ?: e.toString()))
        }
    }

    private fun finishCrypto(
        pending: PendingRequest,
        result: BiometricPrompt.AuthenticationResult,
        privateKey: java.security.PrivateKey,
    ): Response = try {
        when (val r = pending.request) {
            is Request.Sign -> {
                val sig = result.cryptoObject?.signature
                    ?: throw IllegalStateException("no signature in crypto object")
                sig.update(r.data)
                Response.Signature(sig.sign())
            }
            is Request.Ecdh -> {
                val peer = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(r.peerPublicKey))
                val ka = KeyAgreement.getInstance("ECDH", KeyStoreRepo.ANDROID_KEYSTORE)
                ka.init(privateKey)
                ka.doPhase(peer, true)
                Response.SharedSecret(ka.generateSecret())
            }
            else -> Response.Denied
        }
    } catch (e: Exception) {
        Response.Error(e.message ?: e.toString())
    }
}

@Composable
private fun ApprovalScreen(
    pending: PendingRequest?,
    onApprove: (PendingRequest) -> Unit,
    onDeny: (PendingRequest) -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        if (pending == null) return@Column
        when (val r = pending.request) {
            is Request.Pair -> {
                Text("Pair with host?", style = MaterialTheme.typography.headlineSmall)
                Spacer(Modifier.height(16.dp))
                Text(r.hostName, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                Spacer(Modifier.height(24.dp))
                Text(
                    pending.peerId.take(8),
                    fontFamily = FontFamily.Monospace,
                    fontSize = 40.sp,
                    fontWeight = FontWeight.Bold,
                )
                Spacer(Modifier.height(8.dp))
                Text(
                    pending.peerId,
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodySmall,
                )
                Spacer(Modifier.height(32.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
                    OutlinedButton(onClick = { onDeny(pending) }) { Text("Deny") }
                    Button(onClick = { onApprove(pending) }) { Text("Approve") }
                }
            }
            is Request.Sign, is Request.Ecdh -> {
                Text(
                    if (r is Request.Sign) "SSH signature" else "age decrypt",
                    style = MaterialTheme.typography.headlineSmall,
                )
                Spacer(Modifier.height(8.dp))
                Text(pending.hostName, style = MaterialTheme.typography.bodyLarge)
                Spacer(Modifier.height(24.dp))
                CircularProgressIndicator()
                Spacer(Modifier.height(24.dp))
                OutlinedButton(onClick = { onDeny(pending) }, modifier = Modifier.fillMaxWidth()) { Text("Deny") }
            }
            Request.ListKeys, Request.PushEndpoint -> Unit
        }
    }
}
