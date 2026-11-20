package com.islandcompanion.suite.core.rules

import java.util.Locale

/**
 * 高效網域黑名單比對引擎，支援標準 Hosts 檔案與純網域清單匯入。
 *
 * 透過不可變 [Set] 快照搭配 `@Volatile` 確保多執行緒封包讀取路徑無鎖且為 O(L)（L 為網域標籤層數）查詢。
 */
class DomainBlocklistEngine(
    initialDomains: Collection<String> = emptySet(),
) {
    @Volatile
    private var blockedDomains: Set<String> = initialDomains
        .mapNotNull(::normalizeDomain)
        .toSet()

    /**
     * 回傳目前生效的黑名單網域總數。
     */
    val size: Int
        get() = blockedDomains.size

    /**
     * 取得目前所有已正規化的黑名單網域清單。
     */
    fun getBlockedDomains(): Set<String> = blockedDomains

    /**
     * 判斷給定網域是否命中黑名單（支援精確匹配與父網域後綴匹配）。
     * 例如黑名單包含 `tracker.com` 時，會攔截 `tracker.com` 與 `a.b.tracker.com`，
     * 但不會誤殺 `nottracker.com`。
     */
    fun isBlocked(domain: String?): Boolean {
        val normalized = normalizeDomain(domain) ?: return false
        val snapshot = blockedDomains
        if (snapshot.isEmpty()) return false

        var candidate = normalized
        while (true) {
            if (candidate in snapshot) return true
            val dotIndex = candidate.indexOf('.')
            if (dotIndex < 0 || dotIndex == candidate.lastIndex) return false
            candidate = candidate.substring(dotIndex + 1)
        }
    }

    /**
     * 以新的網域集合取代現有黑名單。
     */
    fun replaceAll(domains: Collection<String>) {
        blockedDomains = domains.mapNotNull(::normalizeDomain).toSet()
    }

    /**
     * 新增單一網域至黑名單，回傳正規化後的網域（若格式無效則回傳 `null`）。
     */
    fun addDomain(domain: String): String? {
        val normalized = normalizeDomain(domain) ?: return null
        blockedDomains = blockedDomains + normalized
        return normalized
    }

    /**
     * 自黑名單移除指定網域。
     */
    fun removeDomain(domain: String) {
        val normalized = normalizeDomain(domain) ?: return
        blockedDomains = blockedDomains - normalized
    }

    companion object {
        private val IGNORED_HOSTS = setOf(
            "localhost",
            "localhost.localdomain",
            "local",
            "broadcasthost",
            "ip6-localhost",
            "ip6-loopback",
            "ip6-localnet",
            "ip6-mcastprefix",
            "ip6-allnodes",
            "ip6-allrouters",
            "ip6-allhosts",
            "0.0.0.0",
        )

        /**
         * 解析標準 Hosts 格式（如 `0.0.0.0 ads.example.com`、`127.0.0.1 tracker.net`）、
         * 純網域清單（如 `ads.example.com`、`*.tracker.net`）或 AdGuard 簡易規則（`||ads.example.com^`）。
         */
        fun parseHostsOrDomainList(rawText: String): Set<String> {
            val result = LinkedHashSet<String>()
            rawText.lineSequence().forEach { rawLine ->
                val withoutComment = rawLine
                    .substringBefore('#')
                    .substringBefore('!')
                    .trim()
                if (withoutComment.isEmpty()) return@forEach

                val tokens = withoutComment.split(Regex("\\s+"))
                val candidateToken = when {
                    tokens.size >= 2 && isHostsRedirectPrefix(tokens[0]) -> tokens[1]
                    tokens.size == 1 -> tokens[0]
                    else -> return@forEach
                }

                val cleaned = candidateToken
                    .removePrefix("||")
                    .substringBefore('^')
                    .removePrefix("*.")
                    .removePrefix(".")

                normalizeDomain(cleaned)?.let { normalized ->
                    if (normalized !in IGNORED_HOSTS) {
                        result.add(normalized)
                    }
                }
            }
            return result
        }

        /**
         * 正規化網域名稱（小寫、移除尾端點號與空白），並進行基本格式驗證。
         */
        fun normalizeDomain(raw: String?): String? {
            if (raw.isNullOrBlank()) return null
            val trimmed = raw.trim()
                .lowercase(Locale.ROOT)
                .trimEnd('.')
                .removePrefix("*.")
            if (trimmed.isEmpty() || trimmed.length > 253 || !trimmed.contains('.')) return null
            if (trimmed in IGNORED_HOSTS) return null

            val labels = trimmed.split('.')
            val valid = labels.all { label ->
                label.isNotEmpty() &&
                    label.length <= 63 &&
                    !label.startsWith('-') &&
                    !label.endsWith('-') &&
                    label.all { ch -> ch in 'a'..'z' || ch in '0'..'9' || ch == '-' || ch == '_' }
            }
            return if (valid) trimmed else null
        }

        private fun isHostsRedirectPrefix(token: String): Boolean =
            token == "0.0.0.0" || token == "127.0.0.1" || token == "::" || token == "::1"
    }
}
