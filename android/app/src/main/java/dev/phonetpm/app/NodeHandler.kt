package dev.phonetpm.app

import uniffi.phonetpm_mobile.Handler
import uniffi.phonetpm_mobile.Request
import uniffi.phonetpm_mobile.Response

/**
 * Invoked by the Rust node on a worker thread. Enforces pairing and key
 * existence here; anything needing the user goes through [RequestBroker].
 */
class NodeHandler(private val app: App) : Handler {
    /** Cheap admission check right after the handshake; unpaired peers are dropped outside the window. */
    override fun acceptsPeer(peerId: String): Boolean = app.hosts.isPaired(peerId) || PairingWindow.isOpen()

    override fun handle(peerId: String, request: Request): Response {
        // Unpaired peers never keep the service awake: only a Pair the
        // broker admits to the UI counts as activity (see RequestBroker.submit).
        val host = app.hosts.find(peerId) ?: return when (request) {
            // Denied without any UI unless the user opened the pairing window.
            is Request.Pair -> RequestBroker.submit(app, peerId, sanitizeText(request.hostName, MAX_NAME_CHARS), request)
            else -> Response.Denied
        }
        return NodeService.busy { dispatch(host, request) }
    }

    private fun dispatch(host: PairedHost, request: Request): Response = when (request) {
        is Request.Pair -> Response.Paired(app.push.endpoint)
        Request.ListKeys -> Response.Keys(app.keys.keyInfos())
        Request.PushEndpoint -> Response.PushEndpoint(app.push.endpoint)
        is Request.Sign -> gated(host, request.keyId, request)
        is Request.Ecdh -> gated(host, request.keyId, request)
    }

    private fun gated(host: PairedHost, keyId: String, request: Request): Response {
        if (app.keys.find(keyId) == null) return Response.UnknownKey
        if (request is Request.Ecdh && app.keys.ecdhPeerKey(keyId, request.peerPublicKey) == null) {
            return Response.Error("peer key is not an uncompressed P-256 point on the curve")
        }
        val response = RequestBroker.submit(app, host.peerId, sanitizeText(host.hostName, MAX_NAME_CHARS), request)
        // The user may have removed the host while deciding; it gets nothing then.
        return if (app.hosts.isPaired(host.peerId)) response else Response.Denied
    }
}
