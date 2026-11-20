package com.islandcompanion.suite.feature.netguard.engine

import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import com.islandcompanion.suite.core.rules.BlockReason
import com.islandcompanion.suite.core.rules.DomainBlocklistEngine
import com.islandcompanion.suite.core.rules.IpAddressRules
import com.islandcompanion.suite.core.rules.NetGuardConfig
import com.islandcompanion.suite.core.rules.TrafficAction
import com.islandcompanion.suite.feature.netguard.packet.DnsPacketParser
import com.islandcompanion.suite.feature.netguard.packet.IpPacketHeader
import com.islandcompanion.suite.feature.netguard.packet.IpPacketParser
import hev.htproxy.TProxyService
import java.io.File
import java.io.FileDescriptor
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * TUN 封包前哨層與 `hev-socks5-tunnel`（lwIP）交接橋接器。
 *
 * 透過 `Os.socketpair(AF_UNIX, SOCK_DGRAM, 0)` 建立無狀態封包管線：
 * - `realTunFd`（`VpnService.Builder.setBlocking(true)`）<-> [TunPacketSentinel]
 *   （直接以 `Os.read`/`Os.write` 讀寫，正確處理 `EAGAIN`/`EINTR` 絕不誤退迴圈；
 *   先以原始 5-tuple 查詢 UID、執行私網/mDNS/SSDP/STUN/QUIC 攔截與 DNS DoH/DoT 轉發）
 * - [TunPacketSentinel] <-> `socketpair` <-> `hev-socks5-tunnel`（lwIP 處理完整 TCP/UDP 封包重組）
 *   <-> [LocalPolicySocks5Server]
 */
class TunPacketSentinel(
    private val cacheDir: File,
    private val tunInterface: ParcelFileDescriptor,
    private val localSocks5Port: Int,
    private val configProvider: () -> NetGuardConfig,
    private val blocklistEngine: DomainBlocklistEngine,
    private val uidAppResolver: UidAppResolver,
    private val dnsResolver: EncryptedDnsResolver,
) {
    private val running = AtomicBoolean(false)
    private val tunWriteLock = Any()

    private var sentinelSocketFd: FileDescriptor? = null
    private var lwipPeerPfd: ParcelFileDescriptor? = null
    private var tunReaderThread: Thread? = null
    private var lwipReaderThread: Thread? = null
    private var dnsExecutor: ExecutorService? = null
    private var configFile: File? = null
    private var lwipLogFile: File? = null

    /**
     * 載入原生庫、建立 `socketpair`、啟動 `hev-socks5-tunnel` 核心並驗證存活，
     * 接著啟動雙向封包轉發執行緒。任何失敗都會直接拋出例外，絕不靜默吞掉。
     */
    fun start() {
        if (running.getAndSet(true)) return

        try {
            // 1. 明確驗證原生庫載入（絕不吞掉 UnsatisfiedLinkError）
            System.loadLibrary("hev-socks5-tunnel")

            // 2. 建立 UNIX SOCK_DGRAM socketpair 交接給 lwIP
            val fd0 = FileDescriptor()
            val fd1 = FileDescriptor()
            Os.socketpair(OsConstants.AF_UNIX, OsConstants.SOCK_DGRAM, 0, fd0, fd1)
            configureSocketBuffers(fd0)
            configureSocketBuffers(fd1)

            sentinelSocketFd = fd0
            val peerPfd = ParcelFileDescriptor.dup(fd1)
            runCatching { Os.close(fd1) }
            lwipPeerPfd = peerPfd

            val logFile = File(cacheDir, "hev_tunnel.log").apply {
                if (exists()) delete()
            }
            lwipLogFile = logFile

            val yamlFile = File(cacheDir, "hev_socks5_tunnel.yml").apply {
                writeText(buildHevConfigYaml(localSocks5Port, logFile.absolutePath))
            }
            configFile = yamlFile

            // 3. 啟動 hev-socks5-tunnel（其 JNI 內部會建立獨立 pthread 執行 hev_socks5_tunnel_main）
            val started = TProxyService.TProxyStartService(yamlFile.absolutePath, peerPfd.fd)
            if (!started) {
                error("TProxyStartService 回傳 false（無法建立原生執行緒）")
            }

            // 等待原生執行緒完成 YAML 解析與 lwIP tunnel_init，確認沒有立即異常退出
            Thread.sleep(NATIVE_STARTUP_VERIFY_MS)
            if (!TProxyService.TProxyIsRunning()) {
                val nativeLog = readRecentNativeLog()
                error(
                    if (nativeLog != null) {
                        "hev-socks5-tunnel 初始化後立即中止：$nativeLog"
                    } else {
                        "hev-socks5-tunnel 初始化後立即中止（請檢查設定與權限）"
                    },
                )
            }

            NetGuardRuntimeState.updateLwipStatus("運行中（libhev-socks5-tunnel 已載入）")

            val tunFd = tunInterface.fileDescriptor
            dnsExecutor = Executors.newFixedThreadPool(4)

            // Thread 1: Real TUN -> Sentinel Filter -> lwIP (or DoH/DoT / Drop)
            tunReaderThread = Thread({
                runTunReadLoop(tunFd, fd0)
            }, "NetGuard-TunReader").apply {
                isDaemon = true
                start()
            }

            // Thread 2: lwIP -> Real TUN
            lwipReaderThread = Thread({
                runLwipReturnLoop(fd0, tunFd)
            }, "NetGuard-LwipReader").apply {
                isDaemon = true
                start()
            }
        } catch (t: Throwable) {
            stop()
            throw t
        }
    }

    /**
     * 讀取原生核心目前是否仍存活以及其傳輸統計。
     */
    fun pollNativeHealth(): Boolean {
        val alive = runCatching { TProxyService.TProxyIsRunning() }.getOrDefault(false)
        if (alive) {
            val stats = runCatching { TProxyService.TProxyGetStats() }.getOrNull()
            if (stats != null && stats.size >= 4) {
                NetGuardRuntimeState.updateLwipStatus(
                    "運行中（TX ${stats[0]} 封包 / RX ${stats[2]} 封包）",
                )
            } else {
                NetGuardRuntimeState.updateLwipStatus("運行中")
            }
        } else {
            val nativeLog = readRecentNativeLog()
            val reason = nativeLog ?: "原生執行緒已意外終止"
            NetGuardRuntimeState.updateLwipStatus("異常中止：$reason")
            NetGuardRuntimeState.recordErrorMessage("[lwIP] $reason")
        }
        return alive
    }

    /**
     * 讀取 `hev-socks5-tunnel` 日誌檔最後數行，方便診斷原生初始化問題。
     */
    fun readRecentNativeLog(): String? {
        val file = lwipLogFile ?: return null
        if (!file.exists()) return null
        return runCatching {
            file.readLines()
                .map { it.trim() }
                .filter { it.isNotEmpty() }
                .takeLast(3)
                .joinToString(" | ")
                .ifEmpty { null }
        }.getOrNull()
    }

    /**
     * 安全停止 `hev-socks5-tunnel` 與雙向封包迴圈，釋放所有檔案描述子。
     */
    fun stop() {
        if (!running.getAndSet(false)) return
        runCatching {
            if (TProxyService.TProxyIsRunning()) {
                TProxyService.TProxyStopService()
            }
        }
        dnsExecutor?.shutdownNow()
        dnsExecutor = null
        sentinelSocketFd?.let { fd -> runCatching { Os.close(fd) } }
        sentinelSocketFd = null
        runCatching { lwipPeerPfd?.close() }
        lwipPeerPfd = null
        tunReaderThread?.interrupt()
        lwipReaderThread?.interrupt()
        tunReaderThread = null
        lwipReaderThread = null
        runCatching { configFile?.delete() }
        configFile = null
    }

    private fun runTunReadLoop(tunFd: FileDescriptor, sentinelFd: FileDescriptor) {
        val readBuffer = ByteArray(PACKET_BUFFER_SIZE)
        while (running.get()) {
            val length = try {
                Os.read(tunFd, readBuffer, 0, readBuffer.size)
            } catch (e: ErrnoException) {
                when (e.errno) {
                    OsConstants.EINTR -> continue
                    OsConstants.EAGAIN -> {
                        waitReadable(tunFd)
                        continue
                    }

                    OsConstants.EBADF, OsConstants.ENODEV -> break
                    else -> {
                        if (running.get()) {
                            NetGuardRuntimeState.recordError("TunReader", e)
                        }
                        break
                    }
                }
            } catch (t: Throwable) {
                if (running.get()) {
                    NetGuardRuntimeState.recordError("TunReader", t)
                }
                break
            }

            if (length == 0) {
                waitReadable(tunFd)
                continue
            }
            if (length < 0) break

            NetGuardRuntimeState.recordTunPacketRead()
            handleOutboundPacket(readBuffer, length, tunFd, sentinelFd)
        }
    }

    private fun runLwipReturnLoop(sentinelFd: FileDescriptor, tunFd: FileDescriptor) {
        val returnBuffer = ByteArray(PACKET_BUFFER_SIZE)
        while (running.get()) {
            val length = try {
                Os.read(sentinelFd, returnBuffer, 0, returnBuffer.size)
            } catch (e: ErrnoException) {
                when (e.errno) {
                    OsConstants.EINTR -> continue
                    OsConstants.EAGAIN -> {
                        waitReadable(sentinelFd)
                        continue
                    }

                    OsConstants.EBADF -> break
                    else -> {
                        if (running.get()) {
                            NetGuardRuntimeState.recordError("LwipReader", e)
                        }
                        break
                    }
                }
            } catch (t: Throwable) {
                if (running.get()) {
                    NetGuardRuntimeState.recordError("LwipReader", t)
                }
                break
            }

            if (length <= 0) {
                if (length == 0) {
                    waitReadable(sentinelFd)
                    continue
                }
                break
            }

            writeToTun(tunFd, returnBuffer, length)
            NetGuardRuntimeState.recordLwipReturnPacket()
        }
    }

    private fun waitReadable(fd: FileDescriptor) {
        if (!running.get()) return
        runCatching {
            val pfd = StructPollfd().apply {
                this.fd = fd
                this.events = OsConstants.POLLIN.toShort()
            }
            Os.poll(arrayOf(pfd), POLL_TIMEOUT_MS)
        }
    }

    private fun writeToTun(tunFd: FileDescriptor, data: ByteArray, length: Int) {
        synchronized(tunWriteLock) {
            try {
                Os.write(tunFd, data, 0, length)
            } catch (e: ErrnoException) {
                if (running.get() && e.errno != OsConstants.EAGAIN && e.errno != OsConstants.EINTR) {
                    NetGuardRuntimeState.recordError("TunWrite", e)
                }
            } catch (t: Throwable) {
                if (running.get()) {
                    NetGuardRuntimeState.recordError("TunWrite", t)
                }
            }
        }
    }

    private fun handleOutboundPacket(
        buffer: ByteArray,
        length: Int,
        tunFd: FileDescriptor,
        sentinelFd: FileDescriptor,
    ) {
        val header = IpPacketParser.parse(buffer, length)
        if (header == null) {
            forwardToLwip(sentinelFd, buffer, length)
            return
        }

        val config = configProvider()
        val isTcpOrUdp = header.protocol == IpAddressRules.PROTO_TCP ||
            header.protocol == IpAddressRules.PROTO_UDP

        // 僅於 TCP SYN 或 UDP 封包查詢 UID，減少系統呼叫開銷
        val uid = if (header.isTcpSynOnly || header.protocol == IpAddressRules.PROTO_UDP) {
            uidAppResolver.lookupConnectionOwnerUid(
                protocol = header.protocol,
                sourceIpBytes = header.sourceIpBytes,
                sourcePort = header.sourcePort,
                destinationIpBytes = header.destinationIpBytes,
                destinationPort = header.destinationPort,
            ).also { resolvedUid ->
                if (resolvedUid > 0) {
                    uidAppResolver.rememberDestinationUid(
                        destinationIp = header.destinationIp,
                        destinationPort = header.destinationPort,
                        uid = resolvedUid,
                    )
                }
            }
        } else {
            -1
        }

        // 1. 防 DNS 洩漏：優先攔截明文 UDP 53 查詢，套用黑名單或轉發 DoH/DoT
        if (config.interceptDns && IpAddressRules.isPlaintextDns(header.protocol, header.destinationPort)) {
            if (header.payloadLength >= 12) {
                val queryPayload = buffer.copyOfRange(
                    header.payloadOffset,
                    header.payloadOffset + header.payloadLength,
                )
                handleDnsPacket(header, queryPayload, uid, config, tunFd)
                return
            }
        }

        // 2. 檢查防側漏規則（區網隔離、mDNS/SSDP、WebRTC STUN、QUIC 降級）
        if (isTcpOrUdp) {
            val leakBlockReason = IpAddressRules.evaluatePacketLeakRule(
                destinationIpBytes = header.destinationIpBytes,
                protocol = header.protocol,
                destinationPort = header.destinationPort,
                config = config,
            )
            if (leakBlockReason != null) {
                val app = uidAppResolver.resolveApp(uid)
                NetGuardRuntimeState.recordTraffic(
                    uid = app.uid,
                    appName = app.appName,
                    packageName = app.packageName,
                    protocol = header.protocolName,
                    domain = null,
                    destinationIp = header.destinationIp,
                    destinationPort = header.destinationPort,
                    action = TrafficAction.BLOCKED,
                    reason = leakBlockReason,
                )
                return
            }
        }

        // 3. 其餘合法封包交給 hev-socks5-tunnel（lwIP 核心處理 TCP/UDP 重組與轉發）
        forwardToLwip(sentinelFd, buffer, length)
    }

    private fun handleDnsPacket(
        header: IpPacketHeader,
        queryPayload: ByteArray,
        uid: Int,
        config: NetGuardConfig,
        tunFd: FileDescriptor,
    ) {
        val queryInfo = DnsPacketParser.parseQuery(queryPayload)
        val domain = queryInfo?.domain
        val app = uidAppResolver.resolveApp(uid)

        if (domain != null && blocklistEngine.isBlocked(domain)) {
            val nxDomain = DnsPacketParser.buildNxDomainResponse(queryPayload)
            val responsePacket = DnsPacketParser.wrapUdpResponsePacket(header, nxDomain)
            if (responsePacket != null) {
                writeToTun(tunFd, responsePacket, responsePacket.size)
            }
            NetGuardRuntimeState.recordTraffic(
                uid = app.uid,
                appName = app.appName,
                packageName = app.packageName,
                protocol = "DNS",
                domain = domain,
                destinationIp = header.destinationIp,
                destinationPort = header.destinationPort,
                action = TrafficAction.BLOCKED,
                reason = BlockReason.DNS_BLACKHOLE,
            )
            return
        }

        dnsExecutor?.execute {
            val responsePayload = dnsResolver.resolve(queryPayload, config)
            if (responsePayload != null && running.get()) {
                val responsePacket = DnsPacketParser.wrapUdpResponsePacket(header, responsePayload)
                if (responsePacket != null) {
                    writeToTun(tunFd, responsePacket, responsePacket.size)
                }
            }
            NetGuardRuntimeState.recordTraffic(
                uid = app.uid,
                appName = app.appName,
                packageName = app.packageName,
                protocol = "DNS",
                domain = domain,
                destinationIp = header.destinationIp,
                destinationPort = header.destinationPort,
                action = TrafficAction.ALLOWED,
                reason = null,
            )
        }
    }

    private fun forwardToLwip(sentinelFd: FileDescriptor, buffer: ByteArray, length: Int) {
        try {
            Os.write(sentinelFd, buffer, 0, length)
        } catch (e: ErrnoException) {
            if (running.get() && e.errno != OsConstants.EAGAIN && e.errno != OsConstants.ENOBUFS) {
                NetGuardRuntimeState.recordError("ForwardToLwip", e)
            }
        } catch (t: Throwable) {
            if (running.get()) {
                NetGuardRuntimeState.recordError("ForwardToLwip", t)
            }
        }
    }

    private fun configureSocketBuffers(fd: FileDescriptor) {
        runCatching {
            Os.setsockoptInt(fd, OsConstants.SOL_SOCKET, OsConstants.SO_SNDBUF, SOCKETPAIR_BUF_BYTES)
            Os.setsockoptInt(fd, OsConstants.SOL_SOCKET, OsConstants.SO_RCVBUF, SOCKETPAIR_BUF_BYTES)
        }
    }

    private fun buildHevConfigYaml(socksPort: Int, logFilePath: String): String = """
        tunnel:
          mtu: $TUN_MTU
          ipv4: $TUN_IPV4_ADDR
          ipv6: '$TUN_IPV6_ADDR'
          icmp: 'off'
        socks5:
          port: $socksPort
          address: 127.0.0.1
          udp: 'udp'
        misc:
          log-file: $logFilePath
          log-level: warn
          tcp-buffer-size: 65536
          connect-timeout: 10000
          tcp-read-write-timeout: 300000
          udp-read-write-timeout: 60000
    """.trimIndent()

    companion object {
        const val TUN_MTU = 1500
        const val TUN_IPV4_ADDR = "198.18.0.1"
        const val TUN_DNS_IPV4_ADDR = "198.18.0.2"
        const val TUN_IPV6_ADDR = "2001:db8:1::1"

        private const val PACKET_BUFFER_SIZE = 4_096
        private const val SOCKETPAIR_BUF_BYTES = 512 * 1024
        private const val POLL_TIMEOUT_MS = 200
        private const val NATIVE_STARTUP_VERIFY_MS = 150L
    }
}
