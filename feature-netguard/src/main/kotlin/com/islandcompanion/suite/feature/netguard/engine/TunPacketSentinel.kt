package com.islandcompanion.suite.feature.netguard.engine

import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.OsConstants
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
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * TUN 封包前哨層與 `hev-socks5-tunnel`（lwIP）交接橋接器。
 *
 * 透過 `Os.socketpair(AF_UNIX, SOCK_DGRAM, 0)` 建立無狀態封包管線：
 * - `realTunFd` <-> [TunPacketSentinel]（以原始 5-tuple 查詢 UID、執行私網/mDNS/SSDP/STUN/QUIC 攔截與 DNS DoH/DoT 轉發）
 * - [TunPacketSentinel] <-> `socketpair` <-> `hev-socks5-tunnel`（lwIP 處理完整 TCP 狀態機） <-> [LocalPolicySocks5Server]
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

    /**
     * 建立 `socketpair`、啟動 `hev-socks5-tunnel` 原生核心，並開啟雙向零重度複製的封包轉發迴圈。
     */
    fun start() {
        if (running.getAndSet(true)) return

        val fd0 = FileDescriptor()
        val fd1 = FileDescriptor()
        Os.socketpair(OsConstants.AF_UNIX, OsConstants.SOCK_DGRAM, 0, fd0, fd1)
        configureSocketBuffers(fd0)
        configureSocketBuffers(fd1)

        sentinelSocketFd = fd0
        val peerPfd = ParcelFileDescriptor.dup(fd1)
        runCatching { Os.close(fd1) }
        lwipPeerPfd = peerPfd

        val yamlFile = File(cacheDir, "hev_socks5_tunnel.yml").apply {
            writeText(buildHevConfigYaml(localSocks5Port))
        }
        configFile = yamlFile

        // 傳遞 socketpair 另一端的整數 fd 給 hev-socks5-tunnel（lwIP 核心接管該 fd 讀寫）
        val started = TProxyService.TProxyStartService(yamlFile.absolutePath, peerPfd.fd)
        if (!started) {
            stop()
            error("Failed to start hev-socks5-tunnel native service")
        }

        val tunInput = FileInputStream(tunInterface.fileDescriptor)
        val tunOutput = FileOutputStream(tunInterface.fileDescriptor)
        val sentinelInput = FileInputStream(fd0)
        val sentinelOutput = FileOutputStream(fd0)
        dnsExecutor = Executors.newFixedThreadPool(4)

        // Thread 1: Real TUN -> Sentinel Filter -> lwIP (or DoH/DoT / Drop)
        tunReaderThread = Thread({
            val readBuffer = ByteArray(PACKET_BUFFER_SIZE)
            while (running.get()) {
                val length = runCatching { tunInput.read(readBuffer) }.getOrDefault(-1)
                if (length <= 0) break
                handleOutboundPacket(readBuffer, length, tunOutput, sentinelOutput)
            }
        }, "NetGuard-TunReader").apply {
            isDaemon = true
            start()
        }

        // Thread 2: lwIP -> Real TUN
        lwipReaderThread = Thread({
            val returnBuffer = ByteArray(PACKET_BUFFER_SIZE)
            while (running.get()) {
                val length = runCatching { sentinelInput.read(returnBuffer) }.getOrDefault(-1)
                if (length <= 0) break
                synchronized(tunWriteLock) {
                    runCatching { tunOutput.write(returnBuffer, 0, length) }
                }
            }
        }, "NetGuard-LwipReader").apply {
            isDaemon = true
            start()
        }
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

    private fun handleOutboundPacket(
        buffer: ByteArray,
        length: Int,
        tunOutput: FileOutputStream,
        sentinelOutput: FileOutputStream,
    ) {
        val header = IpPacketParser.parse(buffer, length)
        if (header == null) {
            forwardToLwip(sentinelOutput, buffer, length)
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
                if (header.protocol == IpAddressRules.PROTO_TCP && resolvedUid > 0) {
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

        // 1. 檢查防側漏規則（區網隔離、mDNS/SSDP、WebRTC STUN、QUIC 降級）
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

        // 2. 防 DNS 洩漏：攔截明文 UDP 53 查詢，套用黑名單或轉發 DoH/DoT
        if (config.interceptDns && IpAddressRules.isPlaintextDns(header.protocol, header.destinationPort)) {
            if (header.payloadLength >= 12) {
                val queryPayload = buffer.copyOfRange(
                    header.payloadOffset,
                    header.payloadOffset + header.payloadLength,
                )
                handleDnsPacket(header, queryPayload, uid, config, tunOutput)
                return
            }
        }

        // 3. 其餘合法封包交給 hev-socks5-tunnel（lwIP 核心處理 TCP 重組與轉發）
        forwardToLwip(sentinelOutput, buffer, length)
    }

    private fun handleDnsPacket(
        header: IpPacketHeader,
        queryPayload: ByteArray,
        uid: Int,
        config: NetGuardConfig,
        tunOutput: FileOutputStream,
    ) {
        val queryInfo = DnsPacketParser.parseQuery(queryPayload)
        val domain = queryInfo?.domain
        val app = uidAppResolver.resolveApp(uid)

        if (domain != null && blocklistEngine.isBlocked(domain)) {
            val nxDomain = DnsPacketParser.buildNxDomainResponse(queryPayload)
            val responsePacket = DnsPacketParser.wrapUdpResponsePacket(header, nxDomain)
            if (responsePacket != null) {
                synchronized(tunWriteLock) {
                    runCatching { tunOutput.write(responsePacket) }
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
                    synchronized(tunWriteLock) {
                        runCatching { tunOutput.write(responsePacket) }
                    }
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

    private fun forwardToLwip(sentinelOutput: FileOutputStream, buffer: ByteArray, length: Int) {
        runCatching {
            sentinelOutput.write(buffer, 0, length)
        }
    }

    private fun configureSocketBuffers(fd: FileDescriptor) {
        runCatching {
            Os.setsockoptInt(fd, OsConstants.SOL_SOCKET, OsConstants.SO_SNDBUF, SOCKETPAIR_BUF_BYTES)
            Os.setsockoptInt(fd, OsConstants.SOL_SOCKET, OsConstants.SO_RCVBUF, SOCKETPAIR_BUF_BYTES)
        }
    }

    private fun buildHevConfigYaml(socksPort: Int): String = """
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
        const val TUN_IPV6_ADDR = "fd12:3456:789a::1"

        private const val PACKET_BUFFER_SIZE = 4_096
        private const val SOCKETPAIR_BUF_BYTES = 512 * 1024
    }
}
