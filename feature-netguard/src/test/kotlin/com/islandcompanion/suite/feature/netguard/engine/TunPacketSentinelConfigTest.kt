package com.islandcompanion.suite.feature.netguard.engine

import org.junit.Assert.assertTrue
import org.junit.Test

class TunPacketSentinelConfigTest {

    @Test
    fun buildHevConfigYaml_injectsDynamicSocksPortAndMatchesTunConfig() {
        val yaml = TunPacketSentinel.buildHevConfigYaml(
            socksPort = 43249,
            logFilePath = "/tmp/hev_tunnel.log",
        )

        assertTrue(yaml.contains("mtu: ${TunPacketSentinel.TUN_MTU}"))
        assertTrue(yaml.contains("ipv4: ${TunPacketSentinel.TUN_IPV4_ADDR}"))
        assertTrue(yaml.contains("ipv6: '${TunPacketSentinel.TUN_IPV6_ADDR}'"))
        assertTrue(yaml.contains("port: 43249"))
        assertTrue(yaml.contains("address: 127.0.0.1"))
        assertTrue(yaml.contains("log-file: /tmp/hev_tunnel.log"))
        assertTrue(yaml.contains("log-level: info"))
    }
}
