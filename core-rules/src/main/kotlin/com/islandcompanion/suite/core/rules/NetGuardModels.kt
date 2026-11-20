package com.islandcompanion.suite.core.rules

/**
 * 加密 DNS 上游協定類型。
 */
enum class DnsUpstreamProtocol {
    /** DNS-over-HTTPS（RFC 8484，預設埠 443） */
    DOH,

    /** DNS-over-TLS（RFC 7858，預設埠 853） */
    DOT,
}

/**
 * 本機網路守門員的防側漏與 DNS 設定，所有設定僅存放於本機儲存空間。
 */
data class NetGuardConfig(
    /** 區網隔離：丟棄私網網段（10/8、172.16/12、192.168/16、fc00::/7）與 mDNS/SSDP 封包 */
    val blockLan: Boolean = true,
    /** 防 WebRTC 探測：封鎖常見 STUN/TURN 埠號（UDP 3478、5349） */
    val blockStun: Boolean = true,
    /** QUIC 降級開關：封鎖 UDP 443，強制應用程式回退至 TCP 443 以利 TLS SNI 過濾 */
    val blockQuic: Boolean = true,
    /** 防 DNS 洩漏：攔截明文 UDP 53 並轉發至加密 DoH/DoT 上游 */
    val interceptDns: Boolean = true,
    /** 加密 DNS 上游協定（DoH 或 DoT） */
    val dnsProtocol: DnsUpstreamProtocol = DnsUpstreamProtocol.DOH,
    /** 加密 DNS 上游位址（DoH 為完整 HTTPS URL；DoT 為 hostname 或 hostname:port） */
    val dnsUpstream: String = DEFAULT_DOH_UPSTREAM,
) {
    companion object {
        const val DEFAULT_DOH_UPSTREAM = "https://dns.quad9.net/dns-query"
        const val DEFAULT_DOT_UPSTREAM = "dns.quad9.net"
    }
}

/**
 * 連線處置結果。
 */
enum class TrafficAction {
    ALLOWED,
    BLOCKED,
}

/**
 * 封包或連線遭到攔截的明確原因分類。
 */
enum class BlockReason(val displayLabel: String) {
    LAN_ISOLATION("區網隔離"),
    MDNS_SSDP("mDNS / SSDP"),
    WEBRTC_STUN("WebRTC STUN"),
    QUIC_DOWNGRADE("QUIC 降級"),
    DNS_BLACKHOLE("DNS 黑名單"),
    TLS_SNI_BLOCKLIST("SNI 黑名單"),
}

/**
 * 即時流量日誌單筆紀錄，僅保留於本機記憶體環形緩衝區中。
 */
data class TrafficLogEntry(
    val id: Long,
    val timestampMs: Long,
    val uid: Int,
    val appName: String,
    val packageName: String?,
    val protocol: String,
    val domain: String?,
    val destinationIp: String,
    val destinationPort: Int,
    val action: TrafficAction,
    val reason: BlockReason? = null,
)
