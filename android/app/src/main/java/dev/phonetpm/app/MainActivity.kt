package dev.phonetpm.app

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Person
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.phonetpm_mobile.KeyKind
import java.text.DateFormat
import java.util.Date

class MainActivity : ComponentActivity() {
    private val requestNotifications =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        requestNotificationPermission()
        App.of(this).push.register(this)
        setContent {
            MaterialTheme(colorScheme = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme()) {
                MainScreen(App.of(this))
            }
        }
    }

    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        val granted = ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED
        if (!granted) requestNotifications.launch(Manifest.permission.POST_NOTIFICATIONS)
    }
}

private enum class Tab(val label: String) { Home("Home"), Keys("Keys"), Hosts("Hosts") }

@Composable
private fun MainScreen(app: App) {
    var tab by rememberSaveable { mutableStateOf(Tab.Home) }
    var showCreate by remember { mutableStateOf(false) }
    val snackbar = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()

    Scaffold(
        snackbarHost = { SnackbarHost(snackbar) },
        bottomBar = {
            NavigationBar {
                Tab.entries.forEach { t ->
                    NavigationBarItem(
                        selected = tab == t,
                        onClick = { tab = t },
                        label = { Text(t.label) },
                        icon = {
                            Icon(
                                when (t) {
                                    Tab.Home -> Icons.Default.Home
                                    Tab.Keys -> Icons.Default.Lock
                                    Tab.Hosts -> Icons.Default.Person
                                },
                                contentDescription = t.label,
                            )
                        },
                    )
                }
            }
        },
        floatingActionButton = {
            if (tab == Tab.Keys) {
                FloatingActionButton(onClick = { showCreate = true }) {
                    Icon(Icons.Default.Add, contentDescription = "Create key")
                }
            }
        },
    ) { padding ->
        Column(Modifier.padding(padding).fillMaxSize()) {
            when (tab) {
                Tab.Home -> HomeTab(app)
                Tab.Keys -> KeysTab(app, snackbar)
                Tab.Hosts -> HostsTab(app)
            }
        }
    }

    if (showCreate) {
        CreateKeyDialog(
            onDismiss = { showCreate = false },
            onCreate = { label, kind ->
                showCreate = false
                // StrongBox generation is slow; keep it off the main thread.
                scope.launch(Dispatchers.IO) {
                    val msg = try {
                        val meta = app.keys.create(label, kind)
                        "Created ${meta.label}" + if (meta.strongBox) " (StrongBox)" else ""
                    } catch (e: Exception) {
                        "Key creation failed: ${e.message ?: e}"
                    }
                    snackbar.showSnackbar(msg)
                }
            },
        )
    }
}

@Composable
private fun HomeTab(app: App) {
    val ctx = LocalContext.current
    val running by NodeService.running.collectAsStateWithLifecycle()
    val error by NodeService.error.collectAsStateWithLifecycle()
    var enabled by remember { mutableStateOf(app.identity.serviceEnabled) }
    val endpointId = app.identity.endpointId
    val qr by produceState<ImageBitmap?>(null, endpointId) {
        value = withContext(Dispatchers.Default) { qrBitmap(endpointId, 512).asImageBitmap() }
    }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text("Listen for hosts", style = MaterialTheme.typography.titleMedium)
                Text(
                    when {
                        error != null -> "Error: $error"
                        running -> "Running"
                        enabled && app.push.onDemand -> "Asleep, woken by hosts via UnifiedPush"
                        enabled -> "Starting…"
                        else -> "Stopped"
                    },
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            Switch(
                checked = enabled,
                onCheckedChange = { on ->
                    enabled = on
                    app.identity.serviceEnabled = on
                    if (on) NodeService.start(ctx) else NodeService.stop(ctx)
                },
            )
        }
        HorizontalDivider()
        Text("Endpoint id", style = MaterialTheme.typography.titleMedium)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                endpointId,
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.weight(1f),
            )
            TextButton(onClick = {
                ctx.getSystemService(ClipboardManager::class.java)
                    .setPrimaryClip(ClipData.newPlainText("phonetpm endpoint id", endpointId))
            }) { Text("Copy") }
        }
        qr?.let {
            Image(
                bitmap = it,
                contentDescription = "Endpoint id QR code",
                modifier = Modifier.size(240.dp).align(Alignment.CenterHorizontally),
            )
        }
        Text("On the host, run:", style = MaterialTheme.typography.titleMedium)
        Text(
            "phonetpm pair $endpointId",
            fontFamily = FontFamily.Monospace,
            style = MaterialTheme.typography.bodySmall,
        )
    }
}

@Composable
private fun KeysTab(app: App, snackbar: SnackbarHostState) {
    val keys by app.keys.all.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    var toDelete by remember { mutableStateOf<KeyMeta?>(null) }

    if (keys.isEmpty()) {
        Text(
            "No keys yet. Tap + to create one.",
            modifier = Modifier.padding(16.dp),
            style = MaterialTheme.typography.bodyMedium,
        )
    }
    LazyColumn(Modifier.fillMaxSize()) {
        items(keys, key = { it.id }) { key ->
            val fingerprint = remember(key.id) {
                app.keys.publicKey(key.id)?.let { KeyStoreRepo.fingerprint(it) } ?: "(missing in keystore)"
            }
            Column(
                Modifier
                    .fillMaxWidth()
                    .combinedClickable(onClick = {}, onLongClick = { toDelete = key })
                    .padding(horizontal = 16.dp, vertical = 12.dp),
            ) {
                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(key.label, style = MaterialTheme.typography.titleMedium, modifier = Modifier.weight(1f))
                    AssistChip(onClick = {}, label = { Text(key.kind.name) })
                    if (key.strongBox) AssistChip(onClick = {}, label = { Text("StrongBox") })
                }
                Text(fingerprint, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
            }
            HorizontalDivider()
        }
    }

    toDelete?.let { key ->
        AlertDialog(
            onDismissRequest = { toDelete = null },
            title = { Text("Delete key?") },
            text = { Text("${key.label} will be removed from the Keystore. Hosts using it will lose access.") },
            confirmButton = {
                TextButton(onClick = {
                    toDelete = null
                    scope.launch(Dispatchers.IO) {
                        try {
                            app.keys.delete(key.id)
                        } catch (e: Exception) {
                            snackbar.showSnackbar("Delete failed: ${e.message ?: e}")
                        }
                    }
                }) { Text("Delete") }
            },
            dismissButton = { TextButton(onClick = { toDelete = null }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun CreateKeyDialog(onDismiss: () -> Unit, onCreate: (String, KeyKind) -> Unit) {
    var label by remember { mutableStateOf("") }
    var kind by remember { mutableStateOf(KeyKind.SSH) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("New key") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = label,
                    onValueChange = { label = it },
                    label = { Text("Label") },
                    singleLine = true,
                )
                KeyKind.entries.forEach { k ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        RadioButton(selected = kind == k, onClick = { kind = k })
                        Text(
                            when (k) {
                                KeyKind.SSH -> "SSH (ECDSA P-256 signing)"
                                KeyKind.AGE -> "age (ECDH P-256 decryption)"
                            }
                        )
                    }
                }
            }
        },
        confirmButton = {
            Button(enabled = label.isNotBlank(), onClick = { onCreate(label.trim(), kind) }) { Text("Create") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun HostsTab(app: App) {
    val hosts by app.hosts.all.collectAsStateWithLifecycle()
    var toRemove by remember { mutableStateOf<PairedHost?>(null) }
    val dateFormat = remember { DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT) }

    if (hosts.isEmpty()) {
        Text(
            "No paired hosts. Run `phonetpm pair <endpoint id>` on a host.",
            modifier = Modifier.padding(16.dp),
            style = MaterialTheme.typography.bodyMedium,
        )
    }
    LazyColumn(Modifier.fillMaxSize()) {
        items(hosts, key = { it.peerId }) { host ->
            Row(
                Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(Modifier.weight(1f)) {
                    Text(host.hostName, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Medium)
                    Text(host.peerId, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                    Text("Paired ${dateFormat.format(Date(host.pairedAt))}", style = MaterialTheme.typography.bodySmall)
                }
                IconButton(onClick = { toRemove = host }) {
                    Icon(Icons.Default.Delete, contentDescription = "Remove host")
                }
            }
            HorizontalDivider()
        }
    }

    toRemove?.let { host ->
        AlertDialog(
            onDismissRequest = { toRemove = null },
            title = { Text("Remove host?") },
            text = { Text("${host.hostName} will need to pair again.") },
            confirmButton = {
                TextButton(onClick = {
                    app.hosts.remove(host.peerId)
                    toRemove = null
                }) { Text("Remove") }
            },
            dismissButton = { TextButton(onClick = { toRemove = null }) { Text("Cancel") } },
        )
    }
}
