package com.islandcompanion.suite.feature.netguard.packet

import com.islandcompanion.suite.core.rules.IpAddressRules
import java.net.InetAddress

/**
 * 輕量 IPv4/IPv6 + L4（TCP/UDP）標頭解析結果，供前哨層查詢 UID 與執行防側漏規則，
 * 不維護任何 TCP 狀態機。
 */
data class IpPacketHeader(
    val version: Int,
    val protocol: Int,
    val sourceIpBytes: ByteArray,
    val destinationIpBytes: ByteArray,
    val sourcePort: Int,
    val destinationPort: Int,
    val ipHeaderLength: Int,
    val payloadOffset: Int,
    val payloadLength: Int,
    val isTcpSynOnly: Boolean,
) {
    /** 目標 IP 字串（純數值格式，不觸發 DNS 反查） */
    val destinationIp: String by lazy(LazyThreadSafetyMode.NONE) {
        InetAddress.getByAddress(destinationIpBytes).hostAddress.orEmpty()
    }

    /** 來源 IP 字串（純數值格式，不觸發 DNS 反查） */
    val sourceIp: String by lazy(LazyThreadSafetyMode.NONE) {
        InetAddress.getByAddress(sourceIpBytes).hostAddress.orEmpty()
    }

    val protocolName: String
        get() = when (protocol) {
            IpAddressRules.PROTO_TCP -> "TCP"
            IpAddressRules.PROTO_UDP -> "UDP"
            else -> "IP($protocol)"
        }
}

/**
 * 無狀態 IPv4/IPv6 封包標頭解析器。
 */
object IpPacketParser {

    /**
     * 解析原始 IP 封包緩衝區 [buffer] 中長度為 [length] 的封包標頭。
     * 若封包格式無效或長度不足則回傳 `null`。
     */
    fun parse(buffer: ByteArray, length: Int): IpPacketHeader? {
        if (length < 20) return null
        val version = (buffer[0].toInt() ushr 4) and 0x0F
        return when (version) {
            4 -> parseIpv4(buffer, length)
            6 -> parseIpv6(buffer, length)
            else -> null
        }
    }

    private fun parseIpv4(buffer: ByteArray, length: Int): IpPacketHeader? {
        val ihl = (buffer[0].toInt() and 0x0F) * 4
        if (ihl < 20 || length < ihl) return null

        val totalLength = readUInt16(buffer, 2).coerceAtMost(length)
        if (totalLength < ihl) return null

        val protocol = buffer[9].toInt() and 0xFF
        val srcIp = buffer.copyOfRange(12, 16)
        val dstIp = buffer.copyOfRange(16, 20)

        return parseL4(
            version = 4,
            protocol = protocol,
            srcIp = srcIp,
            dstIp = dstIp,
            buffer = buffer,
            l4Offset = ihl,
            totalLength = totalLength,
        )
    }

    private fun parseIpv6(buffer: ByteArray, length: Int): IpPacketHeader? {
        if (length < 40) return null
        val payloadLen = readUInt16(buffer, 4)
        val totalLength = (40 + payloadLen).coerceAtMost(length)
        val nextHeader = buffer[6].toInt() and 0xFF
        val srcIp = buffer.copyOfRange(8, 24)
        val dstIp = buffer.copyOfRange(24, 40)

        return parseL4(
            version = 6,
            protocol = nextHeader,
            srcIp = srcIp,
            dstIp = dstIp,
            buffer = buffer,
            l4Offset = 40,
            totalLength = totalLength,
        )
    }

    private fun parseL4(
        version: Int,
        protocol: Int,
        srcIp: ByteArray,
        dstIp: ByteArray,
        buffer: ByteArray,
        l4Offset: Int,
        totalLength: Int,
    ): IpPacketHeader? {
        return when (protocol) {
            IpAddressRules.PROTO_UDP -> {
                if (totalLength < l4Offset + 8) return null
                val srcPort = readUInt16(buffer, l4Offset)
                val dstPort = readUInt16(buffer, l4Offset + 2)
                val udpLen = readUInt16(buffer, l4Offset + 4)
                val payloadOffset = l4Offset + 8
                val payloadLength = (udpLen - 8).coerceAtLeast(0).coerceAtMost(totalLength - payloadOffset)
                IpPacketHeader(
                    version = version,
                    protocol = protocol,
                    sourceIpBytes = srcIp,
                    destinationIpBytes = dstIp,
                    sourcePort = srcPort,
                    destinationPort = dstPort,
                    ipHeaderLength = l4Offset,
                    payloadOffset = payloadOffset,
                    payloadLength = payloadLength,
                    isTcpSynOnly = false,
                )
            }

            IpAddressRules.PROTO_TCP -> {
                if (totalLength < l4Offset + 20) return null
                val srcPort = readUInt16(buffer, l4Offset)
                val dstPort = readUInt16(buffer, l4Offset + 2)
                val dataOffset = ((buffer[l4Offset + 12].toInt() ushr 4) and 0x0F) * 4
                if (dataOffset < 20 || totalLength < l4Offset + dataOffset) return null
                val flags = buffer[l4Offset + 13].toInt() and 0xFF
                val synOnly = (flags and 0x02) != 0 && (flags and 0x10) == 0
                val payloadOffset = l4Offset + dataOffset
                IpPacketHeader(
                    version = version,
                    protocol = protocol,
                    sourceIpBytes = srcIp,
                    destinationIpBytes = dstIp,
                    sourcePort = srcPort,
                    destinationPort = dstPort,
                    ipHeaderLength = l4Offset,
                    payloadOffset = payloadOffset,
                    payloadLength = (totalLength - payloadOffset).coerceAtLeast(0),
                    isTcpSynOnly = synOnly,
                )
            }

            else -> IpPacketHeader(
                version = version,
                protocol = protocol,
                sourceIpBytes = srcIp,
                destinationIpBytes = dstIp,
                sourcePort = 0,
                destinationPort = 0,
                ipHeaderLength = l4Offset,
                payloadOffset = l4Offset,
                payloadLength = (totalLength - l4Offset).coerceAtLeast(0),
                isTcpSynOnly = false,
            )
        }
    }

    private fun readUInt16(buf: ByteArray, offset: Int): Int =
        ((buf[offset].toInt() and 0xFF) shl 8) or (buf[offset + 1].toInt() and 0xFF)
}
