package com.islandcompanion.suite.feature.netguard.engine

import com.islandcompanion.suite.core.rules.DnsUpstreamProtocol
import com.islandcompanion.suite.core.rules.NetGuardConfig
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * 加密 DNS 解析器：將攔截到的明文 UDP 53 查詢轉發至使用者自訂的 DoH 或 DoT 上游伺服器。
 *
 * 所有對外 Socket 皆透過 [protectSocket]（即 `VpnService.protect()`）保護，確保不回流進 VPN 造成迴圈。
 */
class EncryptedDnsResolver(
    private val protectSocket: (Socket) -> Boolean,
) {
    /**
     * 依 [config] 設定將原始 DNS 查詢封包 [queryPayload] 送往加密上游並回傳原始 DNS 回應封包。
     * 若連線失敗或逾時則回傳 `null`。
     */
    fun resolve(queryPayload: ByteArray, config: NetGuardConfig): ByteArray? {
        val upstream = config.dnsUpstream.trim().ifEmpty {
            when (config.dnsProtocol) {
                DnsUpstreamProtocol.DOH -> NetGuardConfig.DEFAULT_DOH_UPSTREAM
                DnsUpstreamProtocol.DOT -> NetGuardConfig.DEFAULT_DOT_UPSTREAM
            }
        }
        return when (config.dnsProtocol) {
            DnsUpstreamProtocol.DOH -> resolveViaDoh(queryPayload, upstream)
            DnsUpstreamProtocol.DOT -> resolveViaDot(queryPayload, upstream)
        }
    }

    private fun resolveViaDoh(queryPayload: ByteArray, urlString: String): ByteArray? {
        return runCatching {
            val normalizedUrl = if (urlString.startsWith("https://")) urlString else "https://$urlString"
            val connection = (URL(normalizedUrl).openConnection() as HttpsURLConnection).apply {
                sslSocketFactory = ProtectedSslSocketFactory(
                    delegate = SSLSocketFactory.getDefault() as SSLSocketFactory,
                    protectSocket = protectSocket,
                )
                requestMethod = "POST"
                connectTimeout = CONNECT_TIMEOUT_MS
                readTimeout = READ_TIMEOUT_MS
                doOutput = true
                useCaches = false
                setRequestProperty("Content-Type", "application/dns-message")
                setRequestProperty("Accept", "application/dns-message")
            }
            try {
                connection.outputStream.use { out ->
                    out.write(queryPayload)
                    out.flush()
                }
                if (connection.responseCode == HttpsURLConnection.HTTP_OK) {
                    connection.inputStream.use { it.readBytes() }
                } else {
                    null
                }
            } finally {
                connection.disconnect()
            }
        }.getOrNull()
    }

    private fun resolveViaDot(queryPayload: ByteArray, upstream: String): ByteArray? {
        return runCatching {
            val clean = upstream.removePrefix("tls://").removePrefix("https://").substringBefore('/')
            val host = clean.substringBefore(':')
            val port = clean.substringAfter(':', "853").toIntOrNull() ?: 853
            val rawSocket = Socket()
            protectSocket(rawSocket)
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
                if (responseLen <= 0 || responseLen > MAX_DNS_MESSAGE_BYTES) return@use null
                val response = ByteArray(responseLen)
                input.readFully(response)
                response
            }
        }.getOrNull()
    }

    private class ProtectedSslSocketFactory(
        private val delegate: SSLSocketFactory,
        private val protectSocket: (Socket) -> Boolean,
    ) : SSLSocketFactory() {
        override fun getDefaultCipherSuites(): Array<String> = delegate.defaultCipherSuites
        override fun getSupportedCipherSuites(): Array<String> = delegate.supportedCipherSuites

        override fun createSocket(): Socket = delegate.createSocket().also { protectSocket(it) }

        override fun createSocket(s: Socket?, host: String?, port: Int, autoClose: Boolean): Socket =
            delegate.createSocket(s, host, port, autoClose).also { protectSocket(it) }

        override fun createSocket(host: String?, port: Int): Socket =
            createProtectedConnectedSocket(InetAddress.getByName(host), port, host)

        override fun createSocket(host: String?, port: Int, localHost: InetAddress?, localPort: Int): Socket =
            createProtectedConnectedSocket(InetAddress.getByName(host), port, host)

        override fun createSocket(host: InetAddress?, port: Int): Socket =
            createProtectedConnectedSocket(host!!, port, host.hostAddress)

        override fun createSocket(address: InetAddress?, port: Int, localAddress: InetAddress?, localPort: Int): Socket =
            createProtectedConnectedSocket(address!!, port, address.hostAddress)

        private fun createProtectedConnectedSocket(address: InetAddress, port: Int, sniHost: String?): Socket {
            val plain = Socket()
            protectSocket(plain)
            plain.connect(InetSocketAddress(address, port), CONNECT_TIMEOUT_MS)
            return delegate.createSocket(plain, sniHost ?: address.hostAddress, port, true)
        }
    }

    private companion object {
        const val CONNECT_TIMEOUT_MS = 4_000
        const val READ_TIMEOUT_MS = 4_000
        const val MAX_DNS_MESSAGE_BYTES = 16_384
    }
}
