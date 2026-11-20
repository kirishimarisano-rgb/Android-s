package com.islandcompanion.suite.core.rules

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.core.stringSetPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.netGuardRulesDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "netguard_rules",
)

/**
 * 本機網路守門員設定與網域黑名單持久化儲存介面（嚴格僅存本機）。
 */
interface NetGuardRulesRepository {
    /** 監聽目前防側漏與 DNS 設定 */
    val config: Flow<NetGuardConfig>

    /** 監聽目前已儲存的封鎖網域集合 */
    val blockedDomains: Flow<Set<String>>

    /** 更新防側漏與 DNS 設定 */
    suspend fun updateConfig(transform: (NetGuardConfig) -> NetGuardConfig)

    /** 新增單一網域至黑名單 */
    suspend fun addBlockedDomain(domain: String): Boolean

    /** 自黑名單移除指定網域 */
    suspend fun removeBlockedDomain(domain: String)

    /** 匯入標準 Hosts 或網域清單，回傳本次成功匯入的網域數量 */
    suspend fun importHostsOrDomains(rawText: String, replaceExisting: Boolean = false): Int

    /** 清空所有網域黑名單 */
    suspend fun clearBlockedDomains()
}

/**
 * 基於 Jetpack Preferences DataStore 的本機規則儲存實作。
 */
class DataStoreNetGuardRulesRepository(
    context: Context,
) : NetGuardRulesRepository {
    private val dataStore = context.applicationContext.netGuardRulesDataStore

    override val config: Flow<NetGuardConfig> = dataStore.data.map { prefs ->
        val protocolRaw = prefs[KEY_DNS_PROTOCOL]
        val protocol = DnsUpstreamProtocol.entries.firstOrNull { it.name == protocolRaw }
            ?: DnsUpstreamProtocol.DOH
        NetGuardConfig(
            blockLan = prefs[KEY_BLOCK_LAN] ?: true,
            blockStun = prefs[KEY_BLOCK_STUN] ?: true,
            blockQuic = prefs[KEY_BLOCK_QUIC] ?: true,
            interceptDns = prefs[KEY_INTERCEPT_DNS] ?: true,
            dnsProtocol = protocol,
            dnsUpstream = prefs[KEY_DNS_UPSTREAM] ?: NetGuardConfig.DEFAULT_DOH_UPSTREAM,
        )
    }

    override val blockedDomains: Flow<Set<String>> = dataStore.data.map { prefs ->
        prefs[KEY_BLOCKED_DOMAINS].orEmpty()
    }

    override suspend fun updateConfig(transform: (NetGuardConfig) -> NetGuardConfig) {
        dataStore.edit { prefs ->
            val currentProtocol = DnsUpstreamProtocol.entries
                .firstOrNull { it.name == prefs[KEY_DNS_PROTOCOL] }
                ?: DnsUpstreamProtocol.DOH
            val current = NetGuardConfig(
                blockLan = prefs[KEY_BLOCK_LAN] ?: true,
                blockStun = prefs[KEY_BLOCK_STUN] ?: true,
                blockQuic = prefs[KEY_BLOCK_QUIC] ?: true,
                interceptDns = prefs[KEY_INTERCEPT_DNS] ?: true,
                dnsProtocol = currentProtocol,
                dnsUpstream = prefs[KEY_DNS_UPSTREAM] ?: NetGuardConfig.DEFAULT_DOH_UPSTREAM,
            )
            val updated = transform(current)
            prefs[KEY_BLOCK_LAN] = updated.blockLan
            prefs[KEY_BLOCK_STUN] = updated.blockStun
            prefs[KEY_BLOCK_QUIC] = updated.blockQuic
            prefs[KEY_INTERCEPT_DNS] = updated.interceptDns
            prefs[KEY_DNS_PROTOCOL] = updated.dnsProtocol.name
            prefs[KEY_DNS_UPSTREAM] = updated.dnsUpstream.trim()
        }
    }

    override suspend fun addBlockedDomain(domain: String): Boolean {
        val normalized = DomainBlocklistEngine.normalizeDomain(domain) ?: return false
        dataStore.edit { prefs ->
            val current = prefs[KEY_BLOCKED_DOMAINS].orEmpty()
            prefs[KEY_BLOCKED_DOMAINS] = current + normalized
        }
        return true
    }

    override suspend fun removeBlockedDomain(domain: String) {
        val normalized = DomainBlocklistEngine.normalizeDomain(domain) ?: return
        dataStore.edit { prefs ->
            val current = prefs[KEY_BLOCKED_DOMAINS].orEmpty()
            prefs[KEY_BLOCKED_DOMAINS] = current - normalized
        }
    }

    override suspend fun importHostsOrDomains(rawText: String, replaceExisting: Boolean): Int {
        val parsed = DomainBlocklistEngine.parseHostsOrDomainList(rawText)
        if (parsed.isEmpty()) return 0
        dataStore.edit { prefs ->
            val current = if (replaceExisting) emptySet() else prefs[KEY_BLOCKED_DOMAINS].orEmpty()
            prefs[KEY_BLOCKED_DOMAINS] = current + parsed
        }
        return parsed.size
    }

    override suspend fun clearBlockedDomains() {
        dataStore.edit { prefs ->
            prefs[KEY_BLOCKED_DOMAINS] = emptySet()
        }
    }

    private companion object {
        val KEY_BLOCK_LAN = booleanPreferencesKey("block_lan")
        val KEY_BLOCK_STUN = booleanPreferencesKey("block_stun")
        val KEY_BLOCK_QUIC = booleanPreferencesKey("block_quic")
        val KEY_INTERCEPT_DNS = booleanPreferencesKey("intercept_dns")
        val KEY_DNS_PROTOCOL = stringPreferencesKey("dns_protocol")
        val KEY_DNS_UPSTREAM = stringPreferencesKey("dns_upstream")
        val KEY_BLOCKED_DOMAINS = stringSetPreferencesKey("blocked_domains")
    }
}
