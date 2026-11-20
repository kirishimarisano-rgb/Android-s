package com.islandcompanion.suite.feature.netguard.packet

import com.islandcompanion.suite.core.rules.IpAddressRules
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsPacketParserTest {

    @Test
    fun parseQuery_extractsDomainAndQueryType() {
        val query = buildDnsQuery("ads.example.com", transactionId = 0x1234, qType = 1)

        val info = DnsPacketParser.parseQuery(query)
        assertNotNull(info)
        assertEquals(0x1234, info!!.transactionId)
        assertEquals("ads.example.com", info.domain)
        assertEquals(1, info.queryType)
    }

    @Test
    fun buildNxDomainResponse_setsResponseAndRcode3() {
        val query = buildDnsQuery("tracker.test.org", transactionId = 0xABCD, qType = 28)

        val response = DnsPacketParser.buildNxDomainResponse(query)

        assertEquals(0xAB.toByte(), response[0])
        assertEquals(0xCD.toByte(), response[1])
        // QR bit (0x80) set
        assertTrue((response[2].toInt() and 0x80) != 0)
        // RCODE == 3 (NXDOMAIN)
        assertEquals(3, response[3].toInt() and 0x0F)
    }

    @Test
    fun wrapUdpResponsePacket_swapsEndpointsAndProducesValidIpv4UdpPacket() {
        val query = buildDnsQuery("example.com", transactionId = 0x0042, qType = 1)
        val requestHeader = IpPacketHeader(
            version = 4,
            protocol = IpAddressRules.PROTO_UDP,
            sourceIpBytes = byteArrayOf(198.toByte(), 18, 0, 1),
            destinationIpBytes = byteArrayOf(198.toByte(), 18, 0, 2),
            sourcePort = 51234,
            destinationPort = 53,
            ipHeaderLength = 20,
            payloadOffset = 28,
            payloadLength = query.size,
            isTcpSynOnly = false,
        )

        val wrapped = DnsPacketParser.wrapUdpResponsePacket(
            requestHeader = requestHeader,
            dnsResponsePayload = DnsPacketParser.buildNxDomainResponse(query),
        )
        assertNotNull(wrapped)

        val parsed = IpPacketParser.parse(wrapped!!, wrapped.size)
        assertNotNull(parsed)
        assertEquals("198.18.0.2", parsed!!.sourceIp)
        assertEquals("198.18.0.1", parsed.destinationIp)
        assertEquals(53, parsed.sourcePort)
        assertEquals(51234, parsed.destinationPort)
        assertEquals(query.size, parsed.payloadLength)

        // Verify IPv4 header checksum validates to 0
        assertEquals(0, internetChecksum(wrapped, 0, 20))

        // Verify UDP checksum (with IPv4 pseudo-header) validates to 0
        val udpLen = wrapped.size - 20
        val pseudo = ByteArray(12 + udpLen)
        System.arraycopy(wrapped, 12, pseudo, 0, 8) // srcIp + dstIp
        pseudo[8] = 0
        pseudo[9] = IpAddressRules.PROTO_UDP.toByte()
        pseudo[10] = ((udpLen ushr 8) and 0xFF).toByte()
        pseudo[11] = (udpLen and 0xFF).toByte()
        System.arraycopy(wrapped, 20, pseudo, 12, udpLen)
        assertEquals(0, internetChecksum(pseudo, 0, pseudo.size))
    }

    private fun internetChecksum(data: ByteArray, offset: Int, length: Int): Int {
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

    @Test
    fun buildDnsQuery_andExtractIpv4Answers_roundTripCorrectly() {
        val query = DnsPacketParser.buildDnsQuery("example.com", transactionId = 0x4242)
        val parsed = DnsPacketParser.parseQuery(query)
        assertNotNull(parsed)
        assertEquals("example.com", parsed!!.domain)
        assertEquals(0x4242, parsed.transactionId)

        // Append a standard compressed A record answer for 93.184.215.14
        val response = query.copyOf(query.size + 16)
        response[2] = 0x81.toByte()
        response[3] = 0x80.toByte()
        response[7] = 0x01 // ANCOUNT = 1
        val ans = query.size
        response[ans] = 0xC0.toByte() // compression pointer to offset 12
        response[ans + 1] = 0x0C
        response[ans + 2] = 0x00
        response[ans + 3] = 0x01 // TYPE A
        response[ans + 4] = 0x00
        response[ans + 5] = 0x01 // CLASS IN
        // TTL = 300
        response[ans + 8] = 0x01
        response[ans + 9] = 0x2C
        // RDLENGTH = 4
        response[ans + 10] = 0x00
        response[ans + 11] = 0x04
        // RDATA = 93.184.215.14
        response[ans + 12] = 93
        response[ans + 13] = 184.toByte()
        response[ans + 14] = 215.toByte()
        response[ans + 15] = 14

        val ips = DnsPacketParser.extractIpv4Answers(response)
        assertEquals(listOf("93.184.215.14"), ips)
    }

    private fun buildDnsQuery(domain: String, transactionId: Int, qType: Int): ByteArray {
        val out = ArrayList<Byte>()
        // Header (12 bytes): ID, Flags(RD=1), QDCOUNT=1, AN=0, NS=0, AR=0
        out.add(((transactionId ushr 8) and 0xFF).toByte())
        out.add((transactionId and 0xFF).toByte())
        out.add(0x01)
        out.add(0x00)
        out.add(0x00)
        out.add(0x01)
        repeat(6) { out.add(0x00) }
        // QNAME
        for (label in domain.split('.')) {
            val bytes = label.toByteArray(Charsets.US_ASCII)
            out.add(bytes.size.toByte())
            bytes.forEach { out.add(it) }
        }
        out.add(0x00)
        // QTYPE + QCLASS(IN=1)
        out.add(((qType ushr 8) and 0xFF).toByte())
        out.add((qType and 0xFF).toByte())
        out.add(0x00)
        out.add(0x01)
        return out.toByteArray()
    }
}
