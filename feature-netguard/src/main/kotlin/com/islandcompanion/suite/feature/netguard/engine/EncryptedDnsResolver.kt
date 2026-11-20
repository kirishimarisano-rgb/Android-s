package com.islandcompanion.suite.feature.netguard.engine

import com.islandcompanion.suite.core.rules.DnsUpstreamProtocol
import com.islandcompanion.suite.core.rules.NetGuardConfig
import com.islandcompanion.suite.feature.netguard.packet.DnsPacketParser
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.TimeUnit
import javax.net.SocketFactory
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * 單次加密 DNS 測試結果，用於設定頁「測試 DoH / DoT 連線」診斷按鈕。
 */
data class DnsConnectivityTestResult(
    val success: Boolean,
    val protocolLabel: String,
    val upstream: String,
    val latencyMs: Long,
    val resolvedIps: List<String> = emptyList(),
    val errorMessage: String? = null,
)

/**
 * 加密 DNS 解析器：將攔截到的明文 UDP 53 查詢轉發至使用者自訂的 DoH 或 DoT 上游伺服器。
 *
 * - DoH 採用標準 RFC 8484 `POST` + **OkHttp 4 原生 HTTP/2 (`h2`) 與 HTTP/1.1 協商**：
 *   解決 Android 內建 `HttpsURLConnection` 僅支援 HTTP/1.1 導致 Quad9 等嚴格要求 HTTP/2 的
 *   DoH 伺服器回應 `HTTP 505 Version Not Supported` 的問題，同時支援連線複用降低延遲。
 * - 透過自訂底層 `SocketFactory` 在 `connect()` 前呼叫 `VpnService.protect(socket)`（不覆寫 `SSLSocketFactory`
 *   以免破壞 Conscrypt ALPN `h2` 協商），並搭配 `addDisallowedApplication(packageName)` 雙重防止 VPN 迴圈。
 */
class EncryptedDnsResolver(
    private val protectSocket: (Socket) -> Boolean,
) {
    private val dohClient: OkHttpClient = OkHttpClient.Builder()
        .protocols(listOf(Protocol.HTTP_2, Protocol.HTTP_1_1))
        .socketFactory(ProtectedPlainSocketFactory(protectSocket))
        .connectTimeout(CONNECT_TIMEOUT_MS.toLong(), TimeUnit.MILLISECONDS)
        .readTimeout(READ_TIMEOUT_MS.toLong(), TimeUnit.MILLISECONDS)
        .writeTimeout(READ_TIMEOUT_MS.toLong(), TimeUnit.MILLISECONDS)
        .retryOnConnectionFailure(true)
        .build()

    /**
     * 依 [config] 設定將原始 DNS 查詢封包 [queryPayload] 送往加密上游並回傳原始 DNS 回應封包。
     * 若連線失敗或逾時，會將真實例外或 HTTP 狀態碼記錄至引擎診斷狀態並回傳 `null`。
     */
    fun resolve(queryPayload: ByteArray, config: NetGuardConfig): ByteArray? {
        val result = resolveInternal(queryPayload, config, recordToRuntimeState = true)
        return result.payload
    }

    /**
     * 主動測試目前設定的 DoH / DoT 上游是否可正常解析 `example.com`，可在啟動 VPN 前獨立驗證。
     */
    fun testConnectivity(config: NetGuardConfig, testDomain: String = "example.com"): DnsConnectivityTestResult {
        val startNanos = System.nanoTime()
        val queryPayload = DnsPacketParser.buildDnsQuery(testDomain)
        val upstream = normalizeUpstream(config)
        val outcome = resolveInternal(queryPayload, config, recordToRuntimeState = false)
        val elapsedMs = ((System.nanoTime() - startNanos) / 1_000_000L).coerceAtLeast(1L)

        val payload = outcome.payload
        if (payload == null) {
            return DnsConnectivityTestResult(
                success = false,
                protocolLabel = outcome.protocolLabel,
                upstream = upstream,
                latencyMs = elapsedMs,
                errorMessage = outcome.errorMessage ?: "未知錯誤",
            )
        }

        val ips = DnsPacketParser.extractIpv4Answers(payload)
        return DnsConnectivityTestResult(
            success = ips.isNotEmpty(),
            protocolLabel = outcome.protocolLabel,
            upstream = upstream,
            latencyMs = elapsedMs,
            resolvedIps = ips,
            errorMessage = if (ips.isEmpty()) "上游已回應（${payload.size} bytes），但未包含 A 紀錄" else null,
        )
    }

    private fun resolveInternal(
        queryPayload: ByteArray,
        config: NetGuardConfig,
        recordToRuntimeState: Boolean,
    ): InternalResolveResult {
        val upstream = normalizeUpstream(config)
        return when (config.dnsProtocol) {
            DnsUpstreamProtocol.DOH -> resolveViaDoh(queryPayload, upstream, recordToRuntimeState)
            DnsUpstreamProtocol.DOT -> resolveViaDot(queryPayload, upstream, recordToRuntimeState)
        }
    }

    private fun resolveViaDoh(
        queryPayload: ByteArray,
        urlString: String,
        recordToRuntimeState: Boolean,
    ): InternalResolveResult {
        return try {
            val request = Request.Builder()
                .url(urlString)
                .post(queryPayload.toRequestBody(DNS_MESSAGE_MEDIA_TYPE))
                .header("Accept", DNS_MESSAGE_MIME)
                .build()

            dohClient.newCall(request).execute().use { response ->
                val protoLabel = response.protocol.toString().uppercase()
                if (!response.isSuccessful) {
                    val err = "上游回應 HTTP ${response.code}（$protoLabel，$urlString）"
                    if (recordToRuntimeState) {
                        NetGuardRuntimeState.recordErrorMessage("[DoH] $err")
                    }
                    return InternalResolveResult(
                        payload = null,
                        protocolLabel = protoLabel,
                        errorMessage = err,
                    )
                }
                val body = response.body?.bytes()
                if (body == null || body.size < 12) {
                    val err = "上游回應空內容或長度不足（${body?.size ?: 0} bytes）"
                    if (recordToRuntimeState) {
                        NetGuardRuntimeState.recordErrorMessage("[DoH] $err")
                    }
                    return InternalResolveResult(
                        payload = null,
                        protocolLabel = protoLabel,
                        errorMessage = err,
                    )
                }
                InternalResolveResult(
                    payload = body,
                    protocolLabel = protoLabel,
                    errorMessage = null,
                )
            }
        } catch (t: Throwable) {
            if (recordToRuntimeState) {
                NetGuardRuntimeState.recordError("DoH", t)
            }
            InternalResolveResult(
                payload = null,
                protocolLabel = "DoH",
                errorMessage = "${t::class.java.simpleName}: ${t.message ?: "無詳細訊息"}",
            )
        }
    }

    private fun resolveViaDot(
        queryPayload: ByteArray,
        upstream: String,
        recordToRuntimeState: Boolean,
    ): InternalResolveResult {
        return try {
            val clean = upstream.removePrefix("tls://").removePrefix("https://").substringBefore('/')
            val host = clean.substringBefore(':')
            val port = clean.substringAfter(':', "853").toIntOrNull() ?: 853
            val rawSocket = Socket()
            runCatching { protectSocket(rawSocket) }
            rawSocket.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT_MS)
            rawSocket.soTimeout = READ_TIMEOUT_MS

            val sslFactory = SSLSocketFactory.getDefault() as SSLSocketFactory
            val sslSocket = (sslFactory.createSocket(rawSocket, host, port, true) as SSLSocket).apply {
                soTimeout = READ_TIMEOUT_MS
                startHandshake()
            }
            sslSocket.use { socket ->
                val out = DataOutputStream(socket.outputStream)
                out.writeShort(queryPayload.size)
                out.write(queryPayload)
                out.flush()

                val input = DataInputStream(socket.inputStream)
                val responseLen = input.readUnsignedShort()
                if (responseLen <= 0 || responseLen > MAX_DNS_MESSAGE_BYTES) {
                    val err = "DoT 回應長度異常：$responseLen"
                    if (recordToRuntimeState) {
                        NetGuardRuntimeState.recordErrorMessage("[DoT] $err")
                    }
                    return InternalResolveResult(null, "DoT", err)
                }
                val response = ByteArray(responseLen)
                input.readFully(response)
                InternalResolveResult(response, "DoT", null)
            }
        } catch (t: Throwable) {
            if (recordToRuntimeState) {
                NetGuardRuntimeState.recordError("DoT", t)
            }
            InternalResolveResult(
                payload = null,
                protocolLabel = "DoT",
                errorMessage = "${t::class.java.simpleName}: ${t.message ?: "無詳細訊息"}",
            )
        }
    }

    private fun normalizeUpstream(config: NetGuardConfig): String {
        val raw = config.dnsUpstream.trim().filterNot { it.isWhitespace() }
        if (raw.isEmpty()) {
            return when (config.dnsProtocol) {
                DnsUpstreamProtocol.DOH -> NetGuardConfig.DEFAULT_DOH_UPSTREAM
                DnsUpstreamProtocol.DOT -> NetGuardConfig.DEFAULT_DOT_UPSTREAM
            }
        }
        return when (config.dnsProtocol) {
            DnsUpstreamProtocol.DOH -> {
                if (raw.startsWith("https://") || raw.startsWith("http://")) raw else "https://$raw"
            }

            DnsUpstreamProtocol.DOT -> raw
        }
    }

    private data class InternalResolveResult(
        val payload: ByteArray?,
        val protocolLabel: String,
        val errorMessage: String?,
    )

    /**
     * 包裝 OkHttp 底層明文 TCP Socket，在連線建立前即透過 `VpnService.protect()` 排除 VPN 路由，
     * 同時完整保留 Conscrypt TLS ALPN (`h2`) 協商能力。
     */
    private class ProtectedPlainSocketFactory(
        private val protectSocket: (Socket) -> Boolean,
    ) : SocketFactory() {
        override fun createSocket(): Socket = Socket().also { runCatching { protectSocket(it) } }

        override fun createSocket(host: String?, port: Int): Socket =
            createAndConnect(InetAddress.getByName(host), port, null, 0)

        override fun createSocket(host: String?, port: Int, localHost: InetAddress?, localPort: Int): Socket =
            createAndConnect(InetAddress.getByName(host), port, localHost, localPort)

        override fun createSocket(host: InetAddress?, port: Int): Socket =
            createAndConnect(host!!, port, null, 0)

        override fun createSocket(address: InetAddress?, port: Int, localAddress: InetAddress?, localPort: Int): Socket =
            createAndConnect(address!!, port, localAddress, localPort)

        private fun createAndConnect(
            remote: InetAddress,
            port: Int,
            localAddress: InetAddress?,
            localPort: Int,
        ): Socket {
            val socket = Socket()
            runCatching { protectSocket(socket) }
            if (localAddress != null) {
                socket.bind(InetSocketAddress(localAddress, localPort))
            }
            socket.connect(InetSocketAddress(remote, port), CONNECT_TIMEOUT_MS)
            return socket
        }
    }

    private companion object {
        const val DNS_MESSAGE_MIME = "application/dns-message"
        val DNS_MESSAGE_MEDIA_TYPE = DNS_MESSAGE_MIME.toMediaType()
        const val CONNECT_TIMEOUT_MS = 5_000
        const val READ_TIMEOUT_MS = 5_000
        const val MAX_DNS_MESSAGE_BYTES = 16_384
    }
}
