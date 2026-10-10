package dev.phonetpm.app

import uniffi.phonetpm_mobile.Handler
import uniffi.phonetpm_mobile.Request
import uniffi.phonetpm_mobile.Response

/**
 * Invoked by the Rust node on a worker thread. Enforces pairing and key
 * existence here; anything needing the user goes through [RequestBroker].
 */
class NodeHandler(private val app: App) : Handler {
    override fun handle(peerId: String, request: Request): Response = NodeService.busy { dispatch(peerId, request) }

    private fun dispatch(peerId: String, request: Request): Response {
        val host = app.hosts.find(peerId)
        if (request is Request.Pair) {
            if (host != null) return Response.Paired(app.push.endpoint)
            return RequestBroker.submit(app, peerId, request.hostName, request)
        }
        if (host == null) return Response.Denied
        return when (request) {
            Request.ListKeys -> Response.Keys(app.keys.keyInfos())
            Request.PushEndpoint -> Response.PushEndpoint(app.push.endpoint)
            is Request.Sign -> gated(host.hostName, peerId, request.keyId, request)
            is Request.Ecdh -> gated(host.hostName, peerId, request.keyId, request)
            is Request.Pair -> Response.Paired(app.push.endpoint) // unreachable, handled above
        }
    }

    private fun gated(hostName: String, peerId: String, keyId: String, request: Request): Response {
        if (app.keys.find(keyId) == null) return Response.UnknownKey
        return RequestBroker.submit(app, peerId, hostName, request)
    }
}
