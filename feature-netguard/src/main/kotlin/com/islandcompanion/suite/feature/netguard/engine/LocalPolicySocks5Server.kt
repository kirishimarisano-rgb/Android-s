package com.islandcompanion.suite.feature.netguard.engine

import com.islandcompanion.suite.core.rules.BlockReason
import com.islandcompanion.suite.core.rules.DomainBlocklistEngine
import com.islandcompanion.suite.core.rules.IpAddressRules
import com.islandcompanion.suite.core.rules.NetGuardConfig
import com.islandcompanion.suite.core.rules.TrafficAction
import com.islandcompanion.suite.feature.netguard.packet.TlsSniExtractor
import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * 本機迴路（`127.0.0.1`）SOCKS5 策略代理伺服器，承接 `hev-socks5-tunnel`（lwIP）重組後的 TCP 串流。
 *
 * 職責：
 * 1. 二次驗證目標 IP 區網隔離規則。
 * 2. 僅窺探首段明文 TLS `ClientHello` 的 SNI 網域（絕不終止或解密 HTTPS）。
 * 3. 比對 [DomainBlocklistEngine]：命中黑名單時立即中斷連線；放行時透過 `VpnService.protect()` 直連外部。
 */
class LocalPolicySocks5Server(
    private val configProvider: () -> NetGuardConfig,
    private val blocklistEngine: DomainBlocklistEngine,
    private val uidAppResolver: UidAppResolver,
    private val protectSocket: (Socket) -> Boolean,
) {
    private val running = AtomicBoolean(false)
    private var serverSocket: ServerSocket? = null
    private var acceptThread: Thread? = null
    private var workerPool: ExecutorService? = null

    /**
     * 啟動本機迴路 SOCKS5 監聽器，回傳實際綁定的本機埠號。
     */
    fun start(): Int {
        if (running.getAndSet(true)) {
            return serverSocket?.localPort ?: -1
        }
        val socket = ServerSocket(0, 128, InetAddress.getByName("127.0.0.1"))
        serverSocket = socket
        val pool = Executors.newCachedThreadPool()
        workerPool = pool

        acceptThread = Thread({
            while (running.get() && !socket.isClosed) {
                val client = runCatching { socket.accept() }.getOrNull() ?: break
                pool.execute { handleClient(client) }
            }
        }, "NetGuard-Socks5Accept").apply {
            isDaemon = true
            start()
        }
        return socket.localPort
    }

    /**
     * 停止監聽並釋放所有連線資源。
     */
    fun stop() {
        if (!running.getAndSet(false)) return
        runCatching { serverSocket?.close() }
        serverSocket = null
        workerPool?.shutdownNow()
        workerPool = null
        acceptThread = null
    }

    private fun handleClient(client: Socket) {
        client.use { localSocket ->
            runCatching {
                localSocket.tcpNoDelay = true
                localSocket.soTimeout = HANDSHAKE_TIMEOUT_MS
                val input = localSocket.getInputStream()
                val output = localSocket.getOutputStream()

                // 1. SOCKS5 Greeting: VER(1) NMETHODS(1) METHODS(NMETHODS)
                val ver = input.read()
                if (ver != 0x05) return
                val nMethods = input.read()
                if (nMethods <= 0) return
                val methods = ByteArray(nMethods)
                readFully(input, methods)
                // Reply: VER=5, METHOD=0 (No authentication)
                output.write(byteArrayOf(0x05, 0x00))
                output.flush()

                // 2. SOCKS5 Request: VER CMD RSV ATYP DST.ADDR DST.PORT
                val reqHeader = ByteArray(4)
                readFully(input, reqHeader)
                if (reqHeader[0].toInt() != 0x05) return
                val cmd = reqHeader[1].toInt() and 0xFF
                if (cmd != 0x01) {
                    // Only TCP CONNECT (0x01) is routed through policy relay; UDP is handled at Sentinel
                    sendSocksReply(output, 0x07)
                    return
                }

                val atyp = reqHeader[3].toInt() and 0xFF
                val target = parseTarget(atyp, input) ?: run {
                    sendSocksReply(output, 0x08)
                    return
                }

                val config = configProvider()
                val uid = uidAppResolver.findRecentUidForDestination(target.host, target.port)
                val app = uidAppResolver.resolveApp(uid)

                // Secondary LAN isolation check
                if (config.blockLan && target.ipBytes != null && IpAddressRules.isPrivateOrLanIp(target.ipBytes)) {
                    NetGuardRuntimeState.recordTraffic(
                        uid = app.uid,
                        appName = app.appName,
                        packageName = app.packageName,
                        protocol = "TCP",
                        domain = target.domain,
                        destinationIp = target.host,
                        destinationPort = target.port,
                        action = TrafficAction.BLOCKED,
                        reason = BlockReason.LAN_ISOLATION,
                    )
                    sendSocksReply(output, 0x02) // Connection not allowed by ruleset
                    return
                }

                // Acknowledge SOCKS5 CONNECT so lwIP forwards the client's first payload (e.g. TLS ClientHello)
                sendSocksReply(output, 0x00)

                // Peek first TCP payload to inspect plaintext TLS SNI without terminating TLS
                val peekBuffer = ByteArray(PEEK_BUFFER_SIZE)
                localSocket.soTimeout = SNI_PEEK_TIMEOUT_MS
                val peekLen = try {
                    input.read(peekBuffer)
                } catch (_: SocketTimeoutException) {
                    0
                }
                if (peekLen < 0) return

                val sniDomain = if (peekLen > 0) {
                    TlsSniExtractor.extractSni(peekBuffer, peekLen)
                } else {
                    null
                }
                val effectiveDomain = sniDomain ?: target.domain

                if (effectiveDomain != null && blocklistEngine.isBlocked(effectiveDomain)) {
                    NetGuardRuntimeState.recordTraffic(
                        uid = app.uid,
                        appName = app.appName,
                        packageName = app.packageName,
                        protocol = "TCP",
                        domain = effectiveDomain,
                        destinationIp = target.host,
                        destinationPort = target.port,
                        action = TrafficAction.BLOCKED,
                        reason = BlockReason.TLS_SNI_BLOCKLIST,
                    )
                    return
                }

                // Connect upstream via VpnService.protect() to prevent routing loops
                val upstream = Socket()
                if (!protectSocket(upstream)) {
                    upstream.close()
                    return
                }
                upstream.tcpNoDelay = true
                val remoteAddr = if (target.ipBytes != null) {
                    InetSocketAddress(InetAddress.getByAddress(target.ipBytes), target.port)
                } else {
                    InetSocketAddress(target.host, target.port)
                }
                upstream.connect(remoteAddr, CONNECT_TIMEOUT_MS)

                NetGuardRuntimeState.recordTraffic(
                    uid = app.uid,
                    appName = app.appName,
                    packageName = app.packageName,
                    protocol = "TCP",
                    domain = effectiveDomain,
                    destinationIp = target.host,
                    destinationPort = target.port,
                    action = TrafficAction.ALLOWED,
                    reason = null,
                )

                upstream.use { remoteSocket ->
                    localSocket.soTimeout = 0
                    remoteSocket.soTimeout = 0
                    val remoteOut = remoteSocket.getOutputStream()
                    if (peekLen > 0) {
                        remoteOut.write(peekBuffer, 0, peekLen)
                        remoteOut.flush()
                    }
                    relayBidirectional(localSocket, remoteSocket)
                }
            }
        }
    }

    private fun relayBidirectional(local: Socket, remote: Socket) {
        val pool = workerPool ?: return
        val downstream = pool.submit {
            runCatching {
                pipe(remote.getInputStream(), local.getOutputStream())
            }
            runCatching { local.shutdownOutput() }
        }
        runCatching {
            pipe(local.getInputStream(), remote.getOutputStream())
        }
        runCatching { remote.shutdownOutput() }
        runCatching { downstream.get() }
    }

    private fun pipe(input: InputStream, output: OutputStream) {
        val buffer = ByteArray(RELAY_BUFFER_SIZE)
        while (running.get()) {
            val n = input.read(buffer)
            if (n <= 0) break
            output.write(buffer, 0, n)
            output.flush()
        }
    }

    private fun parseTarget(atyp: Int, input: InputStream): SocksTarget? {
        return when (atyp) {
            0x01 -> {
                val addr = ByteArray(4)
                readFully(input, addr)
                val port = readPort(input)
                SocksTarget(
                    host = InetAddress.getByAddress(addr).hostAddress.orEmpty(),
                    ipBytes = addr,
                    domain = null,
                    port = port,
                )
            }

            0x03 -> {
                val len = input.read()
                if (len <= 0) return null
                val domainBytes = ByteArray(len)
                readFully(input, domainBytes)
                val port = readPort(input)
                val domain = String(domainBytes, Charsets.US_ASCII)
                SocksTarget(host = domain, ipBytes = null, domain = domain, port = port)
            }

            0x04 -> {
                val addr = ByteArray(16)
                readFully(input, addr)
                val port = readPort(input)
                SocksTarget(
                    host = InetAddress.getByAddress(addr).hostAddress.orEmpty(),
                    ipBytes = addr,
                    domain = null,
                    port = port,
                )
            }

            else -> null
        }
    }

    private fun sendSocksReply(output: OutputStream, rep: Int) {
        output.write(
            byteArrayOf(
                0x05,
                rep.toByte(),
                0x00,
                0x01,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
            ),
        )
        output.flush()
    }

    private fun readPort(input: InputStream): Int {
        val hi = input.read()
        val lo = input.read()
        if (hi < 0 || lo < 0) throw EOFException("Unexpected EOF reading port")
        return ((hi and 0xFF) shl 8) or (lo and 0xFF)
    }

    private fun readFully(input: InputStream, buffer: ByteArray) {
        var offset = 0
        while (offset < buffer.size) {
            val read = input.read(buffer, offset, buffer.size - offset)
            if (read < 0) throw EOFException("Unexpected EOF")
            offset += read
        }
    }

    private data class SocksTarget(
        val host: String,
        val ipBytes: ByteArray?,
        val domain: String?,
        val port: Int,
    )

    private companion object {
        const val HANDSHAKE_TIMEOUT_MS = 5_000
        const val SNI_PEEK_TIMEOUT_MS = 1_500
        const val CONNECT_TIMEOUT_MS = 10_000
        const val PEEK_BUFFER_SIZE = 4_096
        const val RELAY_BUFFER_SIZE = 16_384
    }
}
