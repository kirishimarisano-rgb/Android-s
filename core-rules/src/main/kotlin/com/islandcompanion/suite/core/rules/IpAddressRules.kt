package com.islandcompanion.suite.core.rules

import java.net.InetAddress

/**
 * IP 網段與防側漏埠號判斷規則（純函式、無狀態、不觸發 DNS 反查）。
 */
object IpAddressRules {
    const val PROTO_TCP: Int = 6
    const val PROTO_UDP: Int = 17

    const val PORT_DNS: Int = 53
    const val PORT_QUIC: Int = 443
    const val PORT_SSDP: Int = 1900
    const val PORT_STUN: Int = 3478
    const val PORT_STUNS_TURN_TLS: Int = 5349
    const val PORT_MDNS: Int = 5353

    /**
     * 判斷原始 IPv4（4 bytes）或 IPv6（16 bytes）位址是否屬於私網／區網隔離目標：
     * - IPv4：`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、`169.254.0.0/16`（Link-Local）、
     *         `224.0.0.0/4`（Multicast，含 mDNS/SSDP）、`255.255.255.255`（Broadcast）
     * - IPv6：`fc00::/7`（Unique Local Address）、`fe80::/10`（Link-Local）、`ff00::/8`（Multicast）
     */
    fun isPrivateOrLanIp(addressBytes: ByteArray): Boolean = when (addressBytes.size) {
        4 -> isPrivateOrLanIpv4(addressBytes)
        16 -> isPrivateOrLanIpv6(addressBytes)
        else -> false
    }

    /**
     * 判斷字面 IP 字串（IPv4 或 IPv6）是否屬於私網／區網隔離目標。
     * 僅接受數值 IP，避免觸發 DNS 解析。
     */
    fun isPrivateOrLanIp(ipLiteral: String): Boolean {
        val bytes = parseNumericIp(ipLiteral) ?: return false
        return isPrivateOrLanIp(bytes)
    }

    /**
     * 判斷是否為 mDNS（UDP 5353）或 SSDP（UDP 1900）區域網路探索封包。
     */
    fun isMdnsOrSsdp(protocol: Int, destinationPort: Int): Boolean =
        protocol == PROTO_UDP && (destinationPort == PORT_MDNS || destinationPort == PORT_SSDP)

    /**
     * 判斷是否為常見 WebRTC STUN/TURN 探測埠（UDP 3478、5349）。
     */
    fun isStunOrTurn(protocol: Int, destinationPort: Int): Boolean =
        protocol == PROTO_UDP && (destinationPort == PORT_STUN || destinationPort == PORT_STUNS_TURN_TLS)

    /**
     * 判斷是否為 QUIC（UDP 443）封包。
     */
    fun isQuic(protocol: Int, destinationPort: Int): Boolean =
        protocol == PROTO_UDP && destinationPort == PORT_QUIC

    /**
     * 判斷是否為明文 DNS 查詢（UDP 53）。
     */
    fun isPlaintextDns(protocol: Int, destinationPort: Int): Boolean =
        protocol == PROTO_UDP && destinationPort == PORT_DNS

    /**
     * 依目前 [NetGuardConfig] 評估單一封包的防側漏攔截規則，回傳攔截原因或 `null`（放行）。
     */
    fun evaluatePacketLeakRule(
        destinationIpBytes: ByteArray,
        protocol: Int,
        destinationPort: Int,
        config: NetGuardConfig,
    ): BlockReason? {
        if (config.blockLan && isMdnsOrSsdp(protocol, destinationPort)) {
            return BlockReason.MDNS_SSDP
        }
        if (config.blockLan && isPrivateOrLanIp(destinationIpBytes)) {
            return BlockReason.LAN_ISOLATION
        }
        if (config.blockStun && isStunOrTurn(protocol, destinationPort)) {
            return BlockReason.WEBRTC_STUN
        }
        if (config.blockQuic && isQuic(protocol, destinationPort)) {
            return BlockReason.QUIC_DOWNGRADE
        }
        return null
    }

    private fun isPrivateOrLanIpv4(bytes: ByteArray): Boolean {
        val b0 = bytes[0].toInt() and 0xFF
        val b1 = bytes[1].toInt() and 0xFF
        val b2 = bytes[2].toInt() and 0xFF
        val b3 = bytes[3].toInt() and 0xFF

        return when {
            b0 == 10 -> true // 10.0.0.0/8
            b0 == 172 && b1 in 16..31 -> true // 172.16.0.0/12
            b0 == 192 && b1 == 168 -> true // 192.168.0.0/16
            b0 == 169 && b1 == 254 -> true // 169.254.0.0/16 link-local
            b0 in 224..239 -> true // 224.0.0.0/4 multicast
            b0 == 255 && b1 == 255 && b2 == 255 && b3 == 255 -> true // broadcast
            else -> false
        }
    }

    private fun isPrivateOrLanIpv6(bytes: ByteArray): Boolean {
        val b0 = bytes[0].toInt() and 0xFF
        val b1 = bytes[1].toInt() and 0xFF

        // Check IPv4-mapped IPv6 address (::ffff:a.b.c.d)
        val isIpv4Mapped = (0 until 10).all { bytes[it].toInt() == 0 } &&
            (bytes[10].toInt() and 0xFF) == 0xFF &&
            (bytes[11].toInt() and 0xFF) == 0xFF
        if (isIpv4Mapped) {
            return isPrivateOrLanIpv4(bytes.copyOfRange(12, 16))
        }

        return when {
            (b0 and 0xFE) == 0xFC -> true // fc00::/7 Unique Local Address
            b0 == 0xFE && (b1 and 0xC0) == 0x80 -> true // fe80::/10 Link-Local
            b0 == 0xFF -> true // ff00::/8 Multicast
            else -> false
        }
    }

    private fun parseNumericIp(ipLiteral: String): ByteArray? {
        val trimmed = ipLiteral.trim().removeSurrounding("[", "]")
        if (trimmed.isEmpty()) return null
        // Guard against hostnames triggering DNS lookup in InetAddress.getByName
        val looksNumeric = trimmed.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' || it == '.' || it == ':' }
        if (!looksNumeric) return null
        return runCatching { InetAddress.getByName(trimmed).address }.getOrNull()
    }
}
