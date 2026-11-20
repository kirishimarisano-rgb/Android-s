package com.islandcompanion.suite.feature.netguard.engine

import com.islandcompanion.suite.core.rules.BlockReason
import com.islandcompanion.suite.core.rules.DomainBlocklistEngine
import com.islandcompanion.suite.core.rules.IpAddressRules
import com.islandcompanion.suite.core.rules.NetGuardConfig
import com.islandcompanion.suite.core.rules.TrafficAction
import com.islandcompanion.suite.feature.netguard.packet.TlsSniExtractor
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * 本機迴路（`127.0.0.1`）SOCKS5 策略代理伺服器，承接 `hev-socks5-tunnel`（lwIP）重組後的 TCP 與非 DNS UDP 流量。
 *
 * 職責：
 * 1. 二次驗證目標 IP 區網隔離與防側漏規則。
 * 2. 針對 TCP 僅窺探首段明文 TLS `ClientHello` 的 SNI 網域（絕不終止或解密 HTTPS），
 *    比對 [DomainBlocklistEngine]：命中黑名單立即中斷連線；放行則完整轉發首個 `ClientHello` 並透過 `protect()` 直連外部。
 * 3. 支援標準 RFC 1928 `UDP ASSOCIATE (0x03)`，讓放行的非 DNS UDP（例如 NTP 或關閉 QUIC 降級後的 UDP 443）也能正常通行。
 */
class LocalPolicySocks5Server(
    private val configProvider: () -> NetGuardConfig,
    private val blocklistEngine: DomainBlocklistEngine,
    private val lookupAppForTarget: (String, Int) -> AppIdentity,
    private val protectSocket: (Socket) -> Boolean,
    private val protectDatagramSocket: (DatagramSocket) -> Boolean,
) {
    private val running = AtomicBoolean(false)
    private var serverSocket: ServerSocket? = null
    private var acceptThread: Thread? = null
    private var workerPool: ExecutorService? = null

    @Volatile
    private var listeningPort: Int = 0

    /**
     * 啟動本機迴路 SOCKS5 監聽器，回傳實際綁定的本機埠號。
     */
    fun start(): Int {
        if (running.getAndSet(true)) {
            return listeningPort
        }
        val socket = ServerSocket(0, 128, InetAddress.getByName("127.0.0.1"))
        serverSocket = socket
        listeningPort = socket.localPort
        val pool = Executors.newCachedThreadPool()
        workerPool = pool

        NetGuardRuntimeState.updateSocks5Status(
            port = listeningPort,
            status = "監聽 127.0.0.1:$listeningPort（累計 0 / 活躍 0）",
        )

        acceptThread = Thread({
            while (running.get() && !socket.isClosed) {
                val client = try {
                    socket.accept()
                } catch (e: SocketException) {
                    if (running.get()) {
                        NetGuardRuntimeState.recordError("Socks5Accept", e)
                    }
                    break
                } catch (t: Throwable) {
                    if (running.get()) {
                        NetGuardRuntimeState.recordError("Socks5Accept", t)
                    }
                    break
                }
                pool.execute { handleClient(client) }
            }
        }, "NetGuard-Socks5Accept").apply {
            isDaemon = true
            start()
        }
        return listeningPort
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
        listeningPort = 0
        NetGuardRuntimeState.updateSocks5Status(port = 0, status = "已停止")
    }

    private fun handleClient(client: Socket) {
        val port = listeningPort
        NetGuardRuntimeState.recordSocks5ConnectionOpened(port)
        try {
            client.use { localSocket ->
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
                val atyp = reqHeader[3].toInt() and 0xFF
                val target = parseTarget(atyp, input) ?: run {
                    sendSocksReply(output, 0x08)
                    return
                }

                when (cmd) {
                    0x01 -> handleTcpConnect(localSocket, input, output, target)
                    0x03 -> handleUdpAssociate(localSocket, input, output)
                    else -> sendSocksReply(output, 0x07)
                }
            }
        } catch (_: EOFException) {
            // Normal client close during handshake
        } catch (_: SocketException) {
            // Normal connection reset / shutdown
        } catch (t: Throwable) {
            if (running.get()) {
                NetGuardRuntimeState.recordError("Socks5Relay", t)
            }
        } finally {
            NetGuardRuntimeState.recordSocks5ConnectionClosed(port)
        }
    }

    private fun handleTcpConnect(
        localSocket: Socket,
        input: InputStream,
        output: OutputStream,
        target: SocksTarget,
    ) {
        val config = configProvider()
        val app = lookupAppForTarget(target.host, target.port)

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
        val peekTimeout = if (target.port == 443 || target.port == 853 || target.port == 8443) {
            TLS_SNI_PEEK_TIMEOUT_MS
        } else {
            OTHER_TCP_PEEK_TIMEOUT_MS
        }
        localSocket.soTimeout = peekTimeout
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
        try {
            protectSocket(upstream)
            upstream.tcpNoDelay = true
            val remoteAddr = if (target.ipBytes != null) {
                InetSocketAddress(InetAddress.getByAddress(target.ipBytes), target.port)
            } else {
                InetSocketAddress(target.host, target.port)
            }
            upstream.connect(remoteAddr, CONNECT_TIMEOUT_MS)
        } catch (t: Throwable) {
            runCatching { upstream.close() }
            if (running.get()) {
                NetGuardRuntimeState.recordError("TcpConnect(${target.host}:${target.port})", t)
            }
            return
        }

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
            // Forward the entire peeked ClientHello (or initial payload) untouched
            if (peekLen > 0) {
                remoteOut.write(peekBuffer, 0, peekLen)
                remoteOut.flush()
            }
            relayBidirectional(localSocket, remoteSocket)
        }
    }

    /**
     * 處理標準 RFC 1928 `UDP ASSOCIATE (0x03)`，讓放行的非 DNS UDP 封包可透過 `protect()` 正常進出。
     */
    private fun handleUdpAssociate(
        controlSocket: Socket,
        controlInput: InputStream,
        controlOutput: OutputStream,
    ) {
        val localRelay = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        val upstreamUdp = DatagramSocket()
        try {
            protectDatagramSocket(upstreamUdp)
            localRelay.soTimeout = UDP_IDLE_TIMEOUT_MS
            upstreamUdp.soTimeout = UDP_IDLE_TIMEOUT_MS

            sendSocksReply(
                output = controlOutput,
                rep = 0x00,
                bindAddr = byteArrayOf(127, 0, 0, 1),
                bindPort = localRelay.localPort,
            )

            val clientEndpoint = AtomicReference<InetSocketAddress?>(null)
            val active = AtomicBoolean(true)
            val pool = workerPool ?: return

            // Downstream thread: remote UDP -> wrap SOCKS5 UDP header -> localRelay -> hev-socks5-tunnel
            val downstreamTask = pool.submit {
                val recvBuf = ByteArray(UDP_BUFFER_SIZE)
                while (running.get() && active.get() && !upstreamUdp.isClosed) {
                    val pkt = DatagramPacket(recvBuf, recvBuf.size)
                    try {
                        upstreamUdp.receive(pkt)
                    } catch (_: SocketTimeoutException) {
                        continue
                    } catch (_: Throwable) {
                        break
                    }
                    val client = clientEndpoint.get() ?: continue
                    val wrapped = buildSocks5UdpPacket(pkt.address, pkt.port, pkt.data, pkt.length)
                    runCatching {
                        localRelay.send(DatagramPacket(wrapped, wrapped.size, client.address, client.port))
                    }
                }
            }

            // Control socket watcher: closing TCP control channel ends the UDP association
            val controlWatcher = pool.submit {
                runCatching {
                    controlSocket.soTimeout = 0
                    while (running.get() && active.get()) {
                        if (controlInput.read() < 0) break
                    }
                }
                active.set(false)
                runCatching { localRelay.close() }
                runCatching { upstreamUdp.close() }
            }

            // Upstream loop: hev-socks5-tunnel -> unwrap SOCKS5 UDP header -> policy check -> upstreamUdp
            val clientBuf = ByteArray(UDP_BUFFER_SIZE)
            while (running.get() && active.get() && !localRelay.isClosed) {
                val pkt = DatagramPacket(clientBuf, clientBuf.size)
                try {
                    localRelay.receive(pkt)
                } catch (_: SocketTimeoutException) {
                    continue
                } catch (_: Throwable) {
                    break
                }
                clientEndpoint.set(InetSocketAddress(pkt.address, pkt.port))
                val parsed = parseSocks5UdpPacket(pkt.data, pkt.length) ?: continue

                val config = configProvider()
                val ipBytes = parsed.address.address
                val leakReason = IpAddressRules.evaluatePacketLeakRule(
                    destinationIpBytes = ipBytes,
                    protocol = IpAddressRules.PROTO_UDP,
                    destinationPort = parsed.port,
                    config = config,
                )
                val host = parsed.address.hostAddress.orEmpty()
                val app = lookupAppForTarget(host, parsed.port)
                if (leakReason != null) {
                    NetGuardRuntimeState.recordTraffic(
                        uid = app.uid,
                        appName = app.appName,
                        packageName = app.packageName,
                        protocol = "UDP",
                        domain = null,
                        destinationIp = host,
                        destinationPort = parsed.port,
                        action = TrafficAction.BLOCKED,
                        reason = leakReason,
                    )
                    continue
                }

                runCatching {
                    upstreamUdp.send(
                        DatagramPacket(
                            pkt.data,
                            parsed.payloadOffset,
                            parsed.payloadLength,
                            parsed.address,
                            parsed.port,
                        ),
                    )
                    NetGuardRuntimeState.recordTraffic(
                        uid = app.uid,
                        appName = app.appName,
                        packageName = app.packageName,
                        protocol = "UDP",
                        domain = null,
                        destinationIp = host,
                        destinationPort = parsed.port,
                        action = TrafficAction.ALLOWED,
                        reason = null,
                    )
                }.onFailure { err ->
                    if (running.get()) {
                        NetGuardRuntimeState.recordError("UdpRelay($host:${parsed.port})", err)
                    }
                }
            }

            active.set(false)
            runCatching { upstreamUdp.close() }
            runCatching { localRelay.close() }
            runCatching { downstreamTask.cancel(true) }
            runCatching { controlWatcher.cancel(true) }
        } finally {
            runCatching { upstreamUdp.close() }
            runCatching { localRelay.close() }
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

    private fun parseSocks5UdpPacket(data: ByteArray, length: Int): ParsedSocks5Udp? {
        if (length < 10) return null
        val frag = data[2].toInt() and 0xFF
        if (frag != 0) return null // Fragmented SOCKS5 UDP not supported
        val atyp = data[3].toInt() and 0xFF
        var pos = 4
        val address = when (atyp) {
            0x01 -> {
                if (pos + 4 + 2 > length) return null
                val addr = InetAddress.getByAddress(data.copyOfRange(pos, pos + 4))
                pos += 4
                addr
            }

            0x04 -> {
                if (pos + 16 + 2 > length) return null
                val addr = InetAddress.getByAddress(data.copyOfRange(pos, pos + 16))
                pos += 16
                addr
            }

            0x03 -> {
                if (pos + 1 > length) return null
                val len = data[pos].toInt() and 0xFF
                pos += 1
                if (pos + len + 2 > length) return null
                val host = String(data, pos, len, Charsets.US_ASCII)
                pos += len
                runCatching { InetAddress.getByName(host) }.getOrNull() ?: return null
            }

            else -> return null
        }
        val port = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
        pos += 2
        return ParsedSocks5Udp(
            address = address,
            port = port,
            payloadOffset = pos,
            payloadLength = (length - pos).coerceAtLeast(0),
        )
    }

    private fun buildSocks5UdpPacket(
        address: InetAddress,
        port: Int,
        payload: ByteArray,
        payloadLen: Int,
    ): ByteArray {
        val rawAddr = address.address
        val atyp = if (address is Inet4Address || rawAddr.size == 4) 0x01 else 0x04
        val out = ByteArrayOutputStream(6 + rawAddr.size + payloadLen)
        out.write(0x00)
        out.write(0x00)
        out.write(0x00) // FRAG = 0
        out.write(atyp)
        out.write(rawAddr)
        out.write((port ushr 8) and 0xFF)
        out.write(port and 0xFF)
        out.write(payload, 0, payloadLen)
        return out.toByteArray()
    }

    private fun sendSocksReply(
        output: OutputStream,
        rep: Int,
        bindAddr: ByteArray = byteArrayOf(0, 0, 0, 0),
        bindPort: Int = 0,
    ) {
        output.write(
            byteArrayOf(
                0x05,
                rep.toByte(),
                0x00,
                0x01,
                bindAddr[0],
                bindAddr[1],
                bindAddr[2],
                bindAddr[3],
                ((bindPort ushr 8) and 0xFF).toByte(),
                (bindPort and 0xFF).toByte(),
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

    private data class ParsedSocks5Udp(
        val address: InetAddress,
        val port: Int,
        val payloadOffset: Int,
        val payloadLength: Int,
    )

    private companion object {
        const val HANDSHAKE_TIMEOUT_MS = 5_000
        const val TLS_SNI_PEEK_TIMEOUT_MS = 1_500
        const val OTHER_TCP_PEEK_TIMEOUT_MS = 250
        const val CONNECT_TIMEOUT_MS = 10_000
        const val UDP_IDLE_TIMEOUT_MS = 5_000
        const val PEEK_BUFFER_SIZE = 4_096
        const val RELAY_BUFFER_SIZE = 16_384
        const val UDP_BUFFER_SIZE = 4_096
    }
}
