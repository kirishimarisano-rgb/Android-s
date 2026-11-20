package com.islandcompanion.suite.feature.netguard.packet

import com.islandcompanion.suite.core.rules.IpAddressRules
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class IpPacketParserTest {

    @Test
    fun parse_extractsIpv4TcpSynHeaderCorrectly() {
        // Minimal 20-byte IPv4 + 20-byte TCP SYN packet: 198.18.0.1:54321 -> 1.1.1.1:443
        val packet = ByteArray(40)
        packet[0] = 0x45.toByte() // IPv4, IHL=5 (20 bytes)
        packet[2] = 0x00
        packet[3] = 40.toByte()
        packet[9] = IpAddressRules.PROTO_TCP.toByte()
        // Src IP: 198.18.0.1
        packet[12] = 198.toByte()
        packet[13] = 18
        packet[14] = 0
        packet[15] = 1
        // Dst IP: 1.1.1.1
        packet[16] = 1
        packet[17] = 1
        packet[18] = 1
        packet[19] = 1
        // TCP src port 54321 (0xD431), dst port 443 (0x01BB)
        packet[20] = 0xD4.toByte()
        packet[21] = 0x31
        packet[22] = 0x01
        packet[23] = 0xBB.toByte()
        // Data offset = 5 (20 bytes)
        packet[32] = 0x50
        // Flags = SYN only (0x02)
        packet[33] = 0x02

        val header = IpPacketParser.parse(packet, packet.size)
        assertNotNull(header)
        assertEquals(4, header!!.version)
        assertEquals(IpAddressRules.PROTO_TCP, header.protocol)
        assertEquals("198.18.0.1", header.sourceIp)
        assertEquals("1.1.1.1", header.destinationIp)
        assertEquals(54321, header.sourcePort)
        assertEquals(443, header.destinationPort)
        assertTrue(header.isTcpSynOnly)
    }

    @Test
    fun parse_extractsIpv4UdpHeaderAndPayloadOffsets() {
        // 20-byte IPv4 + 8-byte UDP + 4-byte payload: 198.18.0.1:12345 -> 198.18.0.2:53
        val packet = ByteArray(32)
        packet[0] = 0x45.toByte()
        packet[3] = 32.toByte()
        packet[9] = IpAddressRules.PROTO_UDP.toByte()
        packet[12] = 198.toByte()
        packet[13] = 18
        packet[14] = 0
        packet[15] = 1
        packet[16] = 198.toByte()
        packet[17] = 18
        packet[18] = 0
        packet[19] = 2
        // Src port 12345 (0x3039), dst port 53 (0x0035), UDP len 12
        packet[20] = 0x30
        packet[21] = 0x39
        packet[22] = 0x00
        packet[23] = 0x35
        packet[24] = 0x00
        packet[25] = 12

        val header = IpPacketParser.parse(packet, packet.size)
        assertNotNull(header)
        assertEquals(IpAddressRules.PROTO_UDP, header!!.protocol)
        assertEquals(12345, header.sourcePort)
        assertEquals(53, header.destinationPort)
        assertEquals(28, header.payloadOffset)
        assertEquals(4, header.payloadLength)
        assertFalse(header.isTcpSynOnly)
    }

    @Test
    fun parse_returnsNullForTruncatedPacket() {
        assertNull(IpPacketParser.parse(ByteArray(10), 10))
    }
}
