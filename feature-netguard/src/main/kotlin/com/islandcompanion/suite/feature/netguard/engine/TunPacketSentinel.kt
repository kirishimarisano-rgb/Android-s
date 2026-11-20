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
 * 透過 `Os.socketpair(AF_UNIX, SOCK_DGRAM, 0)`（保留單封包邊界）建立雙向管線：
 * - `kotlinSideFd`（僅由 Kotlin 持有）：`TunReader` 寫入待轉發封包；`LwipReader` 讀出 lwIP 回傳的 `SYN-ACK`/資料封包並寫回 `tunFd`。
 * - `nativeSidePfd`（僅傳給 `TProxyService.TProxyStartService`）：由 `hev-socks5-tunnel` lwIP 核心獨占讀寫。
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

    private var kotlinSideFd: FileDescriptor? = null
    private var nativeSidePfd: ParcelFileDescriptor? = null
    private var tunReaderThread: Thread? = null
    private var lwipReaderThread: Thread? = null
    private var dnsExecutor: ExecutorService? = null
    private var configFile: File? = null
    private var lwipLogFile: File? = null

    /**
     * 載入原生庫、建立 `socketpair`、啟動 `hev-socks5-tunnel` 核心並驗證存活，
     * 先啟動回程 `LwipReader` 再啟動去程 `TunReader` 以避免首包 `SYN-ACK` 遺失。
     */
    fun start() {
        if (running.getAndSet(true)) return

        try {
            require(localSocks5Port in 1..65535) {
                "無效的本機 SOCKS5 監聽埠號：$localSocks5Port"
            }

            // 1. 明確驗證原生庫載入（絕不吞掉 UnsatisfiedLinkError）
            System.loadLibrary("hev-socks5-tunnel")

            // 2. 建立 UNIX SOCK_DGRAM socketpair：嚴格區分 kotlinSideFd（Kotlin 讀寫）與 nativeSidePfd（交給 lwIP）
            val kotlinFd = FileDescriptor()
            val nativeFd = FileDescriptor()
            Os.socketpair(OsConstants.AF_UNIX, OsConstants.SOCK_DGRAM, 0, kotlinFd, nativeFd)
            configureSocketBuffers(kotlinFd)
            configureSocketBuffers(nativeFd)

            kotlinSideFd = kotlinFd
            val peerPfd = ParcelFileDescriptor.dup(nativeFd)
            runCatching { Os.close(nativeFd) }
            nativeSidePfd = peerPfd

            val logFile = File(cacheDir, "hev_tunnel.log").apply {
                if (exists()) delete()
            }
            lwipLogFile = logFile

            val yamlContent = buildHevConfigYaml(
                socksPort = localSocks5Port,
                logFilePath = logFile.absolutePath,
            )
            val yamlFile = File(cacheDir, "hev_socks5_tunnel.yml").apply {
                writeText(yamlContent)
            }
            configFile = yamlFile

            // 3. 啟動 hev-socks5-tunnel（傳入 nativeSidePfd.fd，JNI 內部以獨立 pthread 運行）
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

            NetGuardRuntimeState.updateLwipStatus("運行中（fd=${peerPfd.fd}）")

            val tunFd = tunInterface.fileDescriptor
            dnsExecutor = Executors.newFixedThreadPool(4)

            // 4. 先啟動回程執行緒（lwIP -> kotlinSideFd -> Real TUN），確保首個 SYN-ACK 立刻回寫
            lwipReaderThread = Thread({
                runLwipReturnLoop(kotlinFd, tunFd)
            }, "NetGuard-LwipReader").apply {
                isDaemon = true
                start()
            }

            // 5. 再啟動去程執行緒（Real TUN -> Sentinel -> kotlinSideFd -> lwIP 或 DoH/DoT）
            tunReaderThread = Thread({
                runTunReadLoop(tunFd, kotlinFd)
            }, "NetGuard-TunReader").apply {
                isDaemon = true
                start()
            }
        } catch (t: Throwable) {
            stop()
            throw t
        }
    }

    /**
     * 讀取原生核心目前是否仍存活以及其傳輸統計；若已送出封包但 SOCKS5 連線數仍為 0，
     * 主動回報 `hev_tunnel.log` 內最新日誌以利精準排障。
     */
    fun pollNativeHealth(): Boolean {
        val nativeFd = nativeSidePfd?.fd ?: -1
        val alive = runCatching { TProxyService.TProxyIsRunning() }.getOrDefault(false)
        if (alive) {
            val stats = runCatching { TProxyService.TProxyGetStats() }.getOrNull()
            if (stats != null && stats.size >= 4) {
                NetGuardRuntimeState.updateLwipStatus(
                    "運行中（fd=$nativeFd，TX ${stats[0]} / RX ${stats[2]}）",
                )
            } else {
                NetGuardRuntimeState.updateLwipStatus("運行中（fd=$nativeFd）")
            }

            val diag = NetGuardRuntimeState.snapshot.value.diagnostics
            if (diag.sentToLwipPackets >= 5 && diag.socks5TotalConnections == 0L) {
                val nativeLog = readRecentNativeLog()
                if (nativeLog != null && diag.lastError == null) {
                    NetGuardRuntimeState.recordErrorMessage("[lwIP-log] $nativeLog")
                }
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
     * 讀取 `hev-socks5-tunnel` 日誌檔最後數行，方便診斷原生初始化與連線問題。
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
        kotlinSideFd?.let { fd -> runCatching { Os.close(fd) } }
        kotlinSideFd = null
        runCatching { nativeSidePfd?.close() }
        nativeSidePfd = null
        tunReaderThread?.interrupt()
        lwipReaderThread?.interrupt()
        tunReaderThread = null
        lwipReaderThread = null
        runCatching { configFile?.delete() }
        configFile = null
    }

    private fun runTunReadLoop(tunFd: FileDescriptor, kotlinFd: FileDescriptor) {
        val readBuffer = ByteArray(PACKET_BUFFER_SIZE)
        while (running.get()) {
            val length = try {
                Os.read(tunFd, readBuffer, 0, readBuffer.size)
            } catch (e: ErrnoException) {
                when (e.errno) {
                    OsConstants.EINTR -> continue
                    OsConstants.EAGAIN -> {
                        waitForEvent(tunFd, OsConstants.POLLIN)
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
                waitForEvent(tunFd, OsConstants.POLLIN)
                continue
            }
            if (length < 0) break

            NetGuardRuntimeState.recordTunPacketRead()
            handleOutboundPacket(readBuffer, length, tunFd, kotlinFd)
        }
    }

    private fun runLwipReturnLoop(kotlinFd: FileDescriptor, tunFd: FileDescriptor) {
        val returnBuffer = ByteArray(PACKET_BUFFER_SIZE)
        while (running.get()) {
            val length = try {
                Os.read(kotlinFd, returnBuffer, 0, returnBuffer.size)
            } catch (e: ErrnoException) {
                when (e.errno) {
                    OsConstants.EINTR -> continue
                    OsConstants.EAGAIN -> {
                        waitForEvent(kotlinFd, OsConstants.POLLIN)
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
                    waitForEvent(kotlinFd, OsConstants.POLLIN)
                    continue
                }
                break
            }

            if (writeToTun(tunFd, returnBuffer, length)) {
                NetGuardRuntimeState.recordLwipReturnPacket()
            }
        }
    }

    private fun waitForEvent(fd: FileDescriptor, eventMask: Int) {
        if (!running.get()) return
        runCatching {
            val pfd = StructPollfd().apply {
                this.fd = fd
                this.events = eventMask.toShort()
            }
            Os.poll(arrayOf(pfd), POLL_TIMEOUT_MS)
        }
    }

    private fun writeToTun(tunFd: FileDescriptor, data: ByteArray, length: Int): Boolean {
        synchronized(tunWriteLock) {
            return try {
                Os.write(tunFd, data, 0, length) > 0
            } catch (e: ErrnoException) {
                if (running.get() && e.errno != OsConstants.EAGAIN && e.errno != OsConstants.EINTR) {
                    NetGuardRuntimeState.recordError("TunWrite", e)
                }
                false
            } catch (t: Throwable) {
                if (running.get()) {
                    NetGuardRuntimeState.recordError("TunWrite", t)
                }
                false
            }
        }
    }

    private fun handleOutboundPacket(
        buffer: ByteArray,
        length: Int,
        tunFd: FileDescriptor,
        kotlinFd: FileDescriptor,
    ) {
        val header = IpPacketParser.parse(buffer, length)
        if (header == null) {
            forwardToLwip(kotlinFd, buffer, length)
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
        forwardToLwip(kotlinFd, buffer, length)
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
            if (responsePacket != null && writeToTun(tunFd, responsePacket, responsePacket.size)) {
                NetGuardRuntimeState.recordDnsResponseWritten()
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
            if (responsePayload != null && responsePayload.size >= 12 && running.get()) {
                val responsePacket = DnsPacketParser.wrapUdpResponsePacket(header, responsePayload)
                if (responsePacket != null && writeToTun(tunFd, responsePacket, responsePacket.size)) {
                    NetGuardRuntimeState.recordDnsResponseWritten()
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
        }
    }

    private fun forwardToLwip(kotlinFd: FileDescriptor, buffer: ByteArray, length: Int) {
        repeat(2) { attempt ->
            try {
                val written = Os.write(kotlinFd, buffer, 0, length)
                if (written > 0) {
                    NetGuardRuntimeState.recordSentToLwipPacket()
                }
                return
            } catch (e: ErrnoException) {
                if ((e.errno == OsConstants.EAGAIN || e.errno == OsConstants.ENOBUFS) && attempt == 0) {
                    waitForEvent(kotlinFd, OsConstants.POLLOUT)
                } else {
                    if (running.get()) {
                        NetGuardRuntimeState.recordError("ForwardToLwip", e)
                    }
                    return
                }
            } catch (t: Throwable) {
                if (running.get()) {
                    NetGuardRuntimeState.recordError("ForwardToLwip", t)
                }
                return
            }
        }
    }

    private fun configureSocketBuffers(fd: FileDescriptor) {
        runCatching {
            Os.setsockoptInt(fd, OsConstants.SOL_SOCKET, OsConstants.SO_SNDBUF, SOCKETPAIR_BUF_BYTES)
            Os.setsockoptInt(fd, OsConstants.SOL_SOCKET, OsConstants.SO_RCVBUF, SOCKETPAIR_BUF_BYTES)
        }
    }

    companion object {
        /**
         * 與 `hev-socks5-tunnel` 預設 `mtu: 8500` 及 lwIP `TCP_MSS = 8191` 保持一致，
         * 避免大封包透過 `SOCK_DGRAM` `socketpair` 傳遞時遭到截斷。
         */
        const val TUN_MTU = 8500
        const val TUN_IPV4_ADDR = "198.18.0.1"
        const val TUN_DNS_IPV4_ADDR = "198.18.0.2"
        const val TUN_IPV6_ADDR = "2001:db8:1::1"

        private const val PACKET_BUFFER_SIZE = 65_536
        private const val SOCKETPAIR_BUF_BYTES = 1024 * 1024
        private const val POLL_TIMEOUT_MS = 200
        private const val NATIVE_STARTUP_VERIFY_MS = 150L

        /**
         * 產生 `hev-socks5-tunnel` YAML 設定內容（供單元測試與執行期共用，確保動態填入實際 SOCKS5 埠號）。
         */
        fun buildHevConfigYaml(socksPort: Int, logFilePath: String): String = """
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
              log-level: info
              tcp-buffer-size: 65536
              connect-timeout: 10000
              tcp-read-write-timeout: 300000
              udp-read-write-timeout: 60000
        """.trimIndent()
    }
}
