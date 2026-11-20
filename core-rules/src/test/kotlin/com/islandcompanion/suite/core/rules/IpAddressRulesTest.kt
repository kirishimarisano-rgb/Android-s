package com.islandcompanion.suite.core.rules

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress

class IpAddressRulesTest {

    @Test
    fun isPrivateOrLanIp_detectsIpv4PrivateAndMulticastRanges() {
        assertTrue(IpAddressRules.isPrivateOrLanIp("10.0.0.1"))
        assertTrue(IpAddressRules.isPrivateOrLanIp("10.255.255.254"))
        assertTrue(IpAddressRules.isPrivateOrLanIp("172.16.0.1"))
        assertTrue(IpAddressRules.isPrivateOrLanIp("172.31.255.254"))
        assertTrue(IpAddressRules.isPrivateOrLanIp("192.168.0.1"))
        assertTrue(IpAddressRules.isPrivateOrLanIp("192.168.1.100"))
        assertTrue(IpAddressRules.isPrivateOrLanIp("169.254.10.2"))
        assertTrue(IpAddressRules.isPrivateOrLanIp("224.0.0.251")) // mDNS multicast
        assertTrue(IpAddressRules.isPrivateOrLanIp("239.255.255.250")) // SSDP multicast
        assertTrue(IpAddressRules.isPrivateOrLanIp("255.255.255.255"))

        // Public IPv4 & boundary checks
        assertFalse(IpAddressRules.isPrivateOrLanIp("172.15.255.255"))
        assertFalse(IpAddressRules.isPrivateOrLanIp("172.32.0.1"))
        assertFalse(IpAddressRules.isPrivateOrLanIp("1.1.1.1"))
        assertFalse(IpAddressRules.isPrivateOrLanIp("8.8.8.8"))
        assertFalse(IpAddressRules.isPrivateOrLanIp("198.18.0.2"))
    }

    @Test
    fun isPrivateOrLanIp_detectsIpv6UlaLinkLocalMulticastAndMappedIpv4() {
        assertTrue(IpAddressRules.isPrivateOrLanIp("fc00::1"))
        assertTrue(IpAddressRules.isPrivateOrLanIp("fd12:3456:789a::1"))
        assertTrue(IpAddressRules.isPrivateOrLanIp("fe80::1"))
        assertTrue(IpAddressRules.isPrivateOrLanIp("ff02::fb")) // IPv6 mDNS
        assertTrue(IpAddressRules.isPrivateOrLanIp("::ffff:192.168.1.5"))

        assertFalse(IpAddressRules.isPrivateOrLanIp("2606:4700:4700::1111"))
        assertFalse(IpAddressRules.isPrivateOrLanIp("2001:4860:4860::8888"))
        assertFalse(IpAddressRules.isPrivateOrLanIp("::ffff:1.1.1.1"))
    }

    @Test
    fun evaluatePacketLeakRule_respectsIndividualToggles() {
        val publicIp = InetAddress.getByName("1.1.1.1").address
        val lanIp = InetAddress.getByName("192.168.1.1").address

        val allEnabled = NetGuardConfig(
            blockLan = true,
            blockStun = true,
            blockQuic = true,
        )
        assertEquals(
            BlockReason.LAN_ISOLATION,
            IpAddressRules.evaluatePacketLeakRule(lanIp, IpAddressRules.PROTO_TCP, 80, allEnabled),
        )
        assertEquals(
            BlockReason.MDNS_SSDP,
            IpAddressRules.evaluatePacketLeakRule(publicIp, IpAddressRules.PROTO_UDP, 5353, allEnabled),
        )
        assertEquals(
            BlockReason.MDNS_SSDP,
            IpAddressRules.evaluatePacketLeakRule(publicIp, IpAddressRules.PROTO_UDP, 1900, allEnabled),
        )
        assertEquals(
            BlockReason.WEBRTC_STUN,
            IpAddressRules.evaluatePacketLeakRule(publicIp, IpAddressRules.PROTO_UDP, 3478, allEnabled),
        )
        assertEquals(
            BlockReason.WEBRTC_STUN,
            IpAddressRules.evaluatePacketLeakRule(publicIp, IpAddressRules.PROTO_UDP, 5349, allEnabled),
        )
        assertEquals(
            BlockReason.QUIC_DOWNGRADE,
            IpAddressRules.evaluatePacketLeakRule(publicIp, IpAddressRules.PROTO_UDP, 443, allEnabled),
        )
        // TCP 443 must NOT be blocked by QUIC downgrade rule
        assertNull(
            IpAddressRules.evaluatePacketLeakRule(publicIp, IpAddressRules.PROTO_TCP, 443, allEnabled),
        )

        val allDisabled = NetGuardConfig(
            blockLan = false,
            blockStun = false,
            blockQuic = false,
        )
        assertNull(
            IpAddressRules.evaluatePacketLeakRule(lanIp, IpAddressRules.PROTO_UDP, 5353, allDisabled),
        )
        assertNull(
            IpAddressRules.evaluatePacketLeakRule(publicIp, IpAddressRules.PROTO_UDP, 3478, allDisabled),
        )
        assertNull(
            IpAddressRules.evaluatePacketLeakRule(publicIp, IpAddressRules.PROTO_UDP, 443, allDisabled),
        )
    }
}
