package com.islandcompanion.suite.feature.netguard.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.islandcompanion.suite.core.rules.DnsUpstreamProtocol
import com.islandcompanion.suite.core.rules.NetGuardConfig
import com.islandcompanion.suite.core.rules.NetGuardRulesRepository
import com.islandcompanion.suite.core.rules.TrafficLogEntry
import com.islandcompanion.suite.feature.netguard.engine.NetGuardDiagnostics
import com.islandcompanion.suite.feature.netguard.engine.NetGuardRuntimeState
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

/**
 * 網路守門員畫面的單向資料流 UI 狀態。
 */
data class NetGuardUiState(
    val isRunning: Boolean = false,
    val statusMessage: String = "尚未啟動",
    val allowedCount: Long = 0L,
    val blockedCount: Long = 0L,
    val logs: List<TrafficLogEntry> = emptyList(),
    val diagnostics: NetGuardDiagnostics = NetGuardDiagnostics(),
    val config: NetGuardConfig = NetGuardConfig(),
    val blockedDomains: List<String> = emptyList(),
    val feedbackMessage: String? = null,
)

/**
 * 網路守門員 ViewModel，整合執行期流量狀態、引擎診斷資訊與本機規則庫。
 */
class NetGuardViewModel(
    private val rulesRepository: NetGuardRulesRepository,
) : ViewModel() {

    private val feedbackMessage = MutableStateFlow<String?>(null)

    /**
     * 整合 VPN 即時快照、診斷狀態、防側漏設定與黑名單清單的 UI StateFlow。
     */
    val uiState: StateFlow<NetGuardUiState> = combine(
        NetGuardRuntimeState.snapshot,
        rulesRepository.config,
        rulesRepository.blockedDomains,
        feedbackMessage,
    ) { runtime, config, domains, message ->
        NetGuardUiState(
            isRunning = runtime.isRunning,
            statusMessage = runtime.statusMessage,
            allowedCount = runtime.allowedCount,
            blockedCount = runtime.blockedCount,
            logs = runtime.logs,
            diagnostics = runtime.diagnostics,
            config = config,
            blockedDomains = domains.sorted(),
            feedbackMessage = message,
        )
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5_000),
        initialValue = NetGuardUiState(),
    )

    fun setBlockLan(enabled: Boolean) {
        viewModelScope.launch {
            rulesRepository.updateConfig { it.copy(blockLan = enabled) }
        }
    }

    fun setBlockStun(enabled: Boolean) {
        viewModelScope.launch {
            rulesRepository.updateConfig { it.copy(blockStun = enabled) }
        }
    }

    fun setBlockQuic(enabled: Boolean) {
        viewModelScope.launch {
            rulesRepository.updateConfig { it.copy(blockQuic = enabled) }
        }
    }

    fun setInterceptDns(enabled: Boolean) {
        viewModelScope.launch {
            rulesRepository.updateConfig { it.copy(interceptDns = enabled) }
        }
    }

    fun updateDnsUpstream(protocol: DnsUpstreamProtocol, upstream: String) {
        viewModelScope.launch {
            rulesRepository.updateConfig {
                it.copy(
                    dnsProtocol = protocol,
                    dnsUpstream = upstream.trim(),
                )
            }
            feedbackMessage.value = "已更新加密 DNS 上游設定"
        }
    }

    fun addBlockedDomain(domain: String) {
        viewModelScope.launch {
            val ok = rulesRepository.addBlockedDomain(domain)
            feedbackMessage.value = if (ok) {
                "已加入黑名單：$domain"
            } else {
                "網域格式無效：$domain"
            }
        }
    }

    fun removeBlockedDomain(domain: String) {
        viewModelScope.launch {
            rulesRepository.removeBlockedDomain(domain)
            feedbackMessage.value = "已移除封鎖：$domain"
        }
    }

    fun importHostsText(rawText: String, replaceExisting: Boolean = false) {
        viewModelScope.launch {
            val count = rulesRepository.importHostsOrDomains(rawText, replaceExisting)
            feedbackMessage.value = if (count > 0) {
                "成功匯入 $count 筆網域規則"
            } else {
                "未解析到有效網域規則"
            }
        }
    }

    fun clearBlockedDomains() {
        viewModelScope.launch {
            rulesRepository.clearBlockedDomains()
            feedbackMessage.value = "已清空所有網域黑名單"
        }
    }

    fun clearLogs() {
        NetGuardRuntimeState.clearLogsAndCounters()
    }

    fun consumeFeedback() {
        feedbackMessage.value = null
    }

    companion object {
        /**
         * 手動 DI 用的 ViewModelFactory。
         */
        fun provideFactory(
            rulesRepository: NetGuardRulesRepository,
        ): ViewModelProvider.Factory = object : ViewModelProvider.Factory {
            @Suppress("UNCHECKED_CAST")
            override fun <T : ViewModel> create(modelClass: Class<T>): T {
                require(modelClass.isAssignableFrom(NetGuardViewModel::class.java)) {
                    "Unknown ViewModel class: ${modelClass.name}"
                }
                return NetGuardViewModel(rulesRepository) as T
            }
        }
    }
}
