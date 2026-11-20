package com.islandcompanion.suite.feature.netguard.packet

import com.islandcompanion.suite.core.rules.IpAddressRules
import java.io.ByteArrayOutputStream

/**
 * 解析出的 DNS 查詢基本資訊。
 */
data class DnsQueryInfo(
    val transactionId: Int,
    val domain: String,
    val queryType: Int,
)

/**
 * DNS 封包解析與回應封裝工具：
 * - 解析 UDP 53 查詢中的 QNAME / QTYPE。
 * - 當網域命中黑名單時合成標準 NXDOMAIN 回應。
 * - 將 DoH/DoT 回傳的原始 DNS 負載封裝成合法 IPv4/IPv6 + UDP 封包寫回 TUN。
 */
object DnsPacketParser {

    /**
     * 從原始 DNS 訊息（不含 IP/UDP 標頭）解析查詢網域與查詢類型。
     */
    fun parseQuery(dnsPayload: ByteArray, offset: Int = 0, length: Int = dnsPayload.size - offset): DnsQueryInfo? {
        if (length < 12 || offset < 0 || offset + length > dnsPayload.size) return null

        val transactionId = readUInt16(dnsPayload, offset)
        val flags = readUInt16(dnsPayload, offset + 2)
        val isResponse = (flags and 0x8000) != 0
        if (isResponse) return null

        val qdCount = readUInt16(dnsPayload, offset + 4)
        if (qdCount <= 0) return null

        var pos = offset + 12
        val end = offset + length
        val labels = mutableListOf<String>()

        while (pos < end) {
            val labelLen = dnsPayload[pos].toInt() and 0xFF
            if (labelLen == 0) {
                pos++
                break
            }
            // Reject compression pointers in query section
            if ((labelLen and 0xC0) != 0) return null
            pos++
            if (pos + labelLen > end) return null
            labels.add(String(dnsPayload, pos, labelLen, Charsets.US_ASCII))
            pos += labelLen
        }

        if (labels.isEmpty() || pos + 4 > end) return null
        val qType = readUInt16(dnsPayload, pos)
        val domain = labels.joinToString(".").lowercase()

        return DnsQueryInfo(
            transactionId = transactionId,
            domain = domain,
            queryType = qType,
        )
    }

    /**
     * 依據原始 DNS 查詢封包合成標準 `NXDOMAIN`（RCODE = 3）黑洞回應，
     * 供網域黑名單攔截時立即回覆給 App 避免逾時卡頓。
     */
    fun buildNxDomainResponse(queryPayload: ByteArray): ByteArray {
        if (queryPayload.size < 12) return queryPayload
        val response = queryPayload.copyOf()
        // Flags: QR=1 (0x8000), preserve RD (0x0100), RA=1 (0x0080), RCODE=3 NXDOMAIN (0x0003)
        val rdBit = (queryPayload[2].toInt() and 0x01)
        response[2] = (0x80 or rdBit).toByte()
        response[3] = 0x83.toByte()
        // ANCOUNT = 0, NSCOUNT = 0, ARCOUNT = 0
        response[6] = 0
        response[7] = 0
        response[8] = 0
        response[9] = 0
        response[10] = 0
        response[11] = 0
        return response
    }

    /**
     * 將原始 DNS 回應負載封裝為可寫回 TUN 介面的完整 IPv4 或 IPv6 + UDP 封包
     * （來源與目標 IP/Port 對調，並重新計算 IPv4 與 UDP 校驗和）。
     */
    fun wrapUdpResponsePacket(
        requestHeader: IpPacketHeader,
        dnsResponsePayload: ByteArray,
    ): ByteArray? = when (requestHeader.version) {
        4 -> buildIpv4UdpPacket(
            srcIp = requestHeader.destinationIpBytes,
            dstIp = requestHeader.sourceIpBytes,
            srcPort = requestHeader.destinationPort,
            dstPort = requestHeader.sourcePort,
            payload = dnsResponsePayload,
        )

        6 -> buildIpv6UdpPacket(
            srcIp = requestHeader.destinationIpBytes,
            dstIp = requestHeader.sourceIpBytes,
            srcPort = requestHeader.destinationPort,
            dstPort = requestHeader.sourcePort,
            payload = dnsResponsePayload,
        )

        else -> null
    }

    private fun buildIpv4UdpPacket(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray,
    ): ByteArray {
        val udpLen = 8 + payload.size
        val totalLen = 20 + udpLen
        val packet = ByteArray(totalLen)

        // IPv4 Header (20 bytes)
        packet[0] = 0x45.toByte() // Version 4, IHL 5
        packet[1] = 0x00
        writeUInt16(packet, 2, totalLen)
        writeUInt16(packet, 4, 0) // Identification
        writeUInt16(packet, 6, 0x4000) // Don't Fragment
        packet[8] = 64.toByte() // TTL
        packet[9] = IpAddressRules.PROTO_UDP.toByte()
        System.arraycopy(srcIp, 0, packet, 12, 4)
        System.arraycopy(dstIp, 0, packet, 16, 4)
        writeUInt16(packet, 10, computeChecksum(packet, 0, 20))

        // UDP Header (8 bytes)
        writeUInt16(packet, 20, srcPort)
        writeUInt16(packet, 22, dstPort)
        writeUInt16(packet, 24, udpLen)
        writeUInt16(packet, 26, 0)
        System.arraycopy(payload, 0, packet, 28, payload.size)

        val udpChecksum = computeIpv4UdpChecksum(srcIp, dstIp, packet, 20, udpLen)
        writeUInt16(packet, 26, udpChecksum)
        return packet
    }

    private fun buildIpv6UdpPacket(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray,
    ): ByteArray {
        val udpLen = 8 + payload.size
        val packet = ByteArray(40 + udpLen)

        // IPv6 Header (40 bytes)
        packet[0] = 0x60.toByte() // Version 6
        writeUInt16(packet, 4, udpLen)
        packet[6] = IpAddressRules.PROTO_UDP.toByte()
        packet[7] = 64.toByte() // Hop Limit
        System.arraycopy(srcIp, 0, packet, 8, 16)
        System.arraycopy(dstIp, 0, packet, 24, 16)

        // UDP Header (8 bytes)
        writeUInt16(packet, 40, srcPort)
        writeUInt16(packet, 42, dstPort)
        writeUInt16(packet, 44, udpLen)
        writeUInt16(packet, 46, 0)
        System.arraycopy(payload, 0, packet, 48, payload.size)

        val udpChecksum = computeIpv6UdpChecksum(srcIp, dstIp, packet, 40, udpLen)
        writeUInt16(packet, 46, udpChecksum)
        return packet
    }

    private fun computeChecksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) {
            sum += (data[i].toInt() and 0xFF) shl 8
        }
        while ((sum ushr 16) != 0L) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return (sum.inv() and 0xFFFF).toInt()
    }

    private fun computeIpv4UdpChecksum(
        srcIp: ByteArray,
        dstIp: ByteArray,
        packet: ByteArray,
        udpOffset: Int,
        udpLength: Int,
    ): Int {
        val pseudo = ByteArrayOutputStream(12 + udpLength)
        pseudo.write(srcIp)
        pseudo.write(dstIp)
        pseudo.write(0)
        pseudo.write(IpAddressRules.PROTO_UDP)
        pseudo.write((udpLength ushr 8) and 0xFF)
        pseudo.write(udpLength and 0xFF)
        pseudo.write(packet, udpOffset, udpLength)
        val raw = computeChecksum(pseudo.toByteArray(), 0, pseudo.size())
        return if (raw == 0) 0xFFFF else raw
    }

    private fun computeIpv6UdpChecksum(
        srcIp: ByteArray,
        dstIp: ByteArray,
        packet: ByteArray,
        udpOffset: Int,
        udpLength: Int,
    ): Int {
        val pseudo = ByteArrayOutputStream(40 + udpLength)
        pseudo.write(srcIp)
        pseudo.write(dstIp)
        pseudo.write((udpLength ushr 24) and 0xFF)
        pseudo.write((udpLength ushr 16) and 0xFF)
        pseudo.write((udpLength ushr 8) and 0xFF)
        pseudo.write(udpLength and 0xFF)
        pseudo.write(0)
        pseudo.write(0)
        pseudo.write(0)
        pseudo.write(IpAddressRules.PROTO_UDP)
        pseudo.write(packet, udpOffset, udpLength)
        val raw = computeChecksum(pseudo.toByteArray(), 0, pseudo.size())
        return if (raw == 0) 0xFFFF else raw
    }

    private fun readUInt16(buf: ByteArray, offset: Int): Int =
        ((buf[offset].toInt() and 0xFF) shl 8) or (buf[offset + 1].toInt() and 0xFF)

    private fun writeUInt16(buf: ByteArray, offset: Int, value: Int) {
        buf[offset] = ((value ushr 8) and 0xFF).toByte()
        buf[offset + 1] = (value and 0xFF).toByte()
    }
}
