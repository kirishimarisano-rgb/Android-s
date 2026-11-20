package com.islandcompanion.suite.feature.netguard.engine

import com.islandcompanion.suite.core.rules.BlockReason
import com.islandcompanion.suite.core.rules.TrafficAction
import com.islandcompanion.suite.core.rules.TrafficLogEntry
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * 引擎即時診斷狀態，協助即時排查 TUN 讀寫、socketpair 交接、lwIP 原生核心與本機 SOCKS5 策略代理狀況。
 */
data class NetGuardDiagnostics(
    val tunReadPackets: Long = 0L,
    val sentToLwipPackets: Long = 0L,
    val lwipReturnPackets: Long = 0L,
    val dnsResponsesWritten: Long = 0L,
    val lwipStatus: String = "未啟動",
    val socks5Port: Int = 0,
    val socks5TotalConnections: Long = 0L,
    val socks5ActiveConnections: Int = 0,
    val socks5Status: String = "未啟動",
    val lastError: String? = null,
)

/**
 * 本機網路守門員的即時執行期狀態快照。
 */
data class NetGuardRuntimeSnapshot(
    val isRunning: Boolean = false,
    val allowedCount: Long = 0L,
    val blockedCount: Long = 0L,
    val statusMessage: String = "尚未啟動",
    val logs: List<TrafficLogEntry> = emptyList(),
    val diagnostics: NetGuardDiagnostics = NetGuardDiagnostics(),
)

/**
 * 執行期共享狀態匯流排（單向資料流），供 [NetGuardVpnService] 寫入統計、診斷與日誌，
 * 並讓 Compose UI 與前景通知即時訂閱。所有資料僅存於本機記憶體。
 */
object NetGuardRuntimeState {
    private const val MAX_LOG_ENTRIES = 200
    private val nextId = AtomicLong(1L)
    private val tunReadCounter = AtomicLong(0L)
    private val sentToLwipCounter = AtomicLong(0L)
    private val lwipReturnCounter = AtomicLong(0L)
    private val dnsResponseCounter = AtomicLong(0L)
    private val socksTotalCounter = AtomicLong(0L)
    private val socksActiveCounter = AtomicInteger(0)

    private val _snapshot = MutableStateFlow(NetGuardRuntimeSnapshot())

    /**
     * 即時狀態串流。
     */
    val snapshot: StateFlow<NetGuardRuntimeSnapshot> = _snapshot.asStateFlow()

    /**
     * 更新 VPN 執行狀態與狀態訊息。
     */
    fun setRunning(running: Boolean, statusMessage: String) {
        _snapshot.update { current ->
            current.copy(
                isRunning = running,
                statusMessage = statusMessage,
            )
        }
    }

    /**
     * 啟動新連線會話前重設診斷計數與錯誤訊息。
     */
    fun resetSessionDiagnostics() {
        tunReadCounter.set(0L)
        sentToLwipCounter.set(0L)
        lwipReturnCounter.set(0L)
        dnsResponseCounter.set(0L)
        socksTotalCounter.set(0L)
        socksActiveCounter.set(0)
        _snapshot.update { current ->
            current.copy(
                diagnostics = NetGuardDiagnostics(
                    tunReadPackets = 0L,
                    sentToLwipPackets = 0L,
                    lwipReturnPackets = 0L,
                    dnsResponsesWritten = 0L,
                    lwipStatus = "初始化中…",
                    socks5Port = 0,
                    socks5TotalConnections = 0L,
                    socks5ActiveConnections = 0,
                    socks5Status = "初始化中…",
                    lastError = null,
                ),
            )
        }
    }

    /**
     * 只要從 TUN 介面讀到任何原始封包位元組即立即遞增。
     */
    fun recordTunPacketRead() {
        val count = tunReadCounter.incrementAndGet()
        _snapshot.update { current ->
            current.copy(
                diagnostics = current.diagnostics.copy(tunReadPackets = count),
            )
        }
    }

    /**
     * 記錄透過 socketpair 成功送往 lwIP 核心的封包數。
     */
    fun recordSentToLwipPacket() {
        val count = sentToLwipCounter.incrementAndGet()
        _snapshot.update { current ->
            current.copy(
                diagnostics = current.diagnostics.copy(sentToLwipPackets = count),
            )
        }
    }

    /**
     * 記錄自 lwIP 核心回寫至真實 TUN 的封包數。
     */
    fun recordLwipReturnPacket() {
        val count = lwipReturnCounter.incrementAndGet()
        _snapshot.update { current ->
            current.copy(
                diagnostics = current.diagnostics.copy(lwipReturnPackets = count),
            )
        }
    }

    /**
     * 記錄成功寫回 TUN 的加密 DNS（DoH / DoT）或黑洞回應封包數。
     */
    fun recordDnsResponseWritten() {
        val count = dnsResponseCounter.incrementAndGet()
        _snapshot.update { current ->
            current.copy(
                diagnostics = current.diagnostics.copy(dnsResponsesWritten = count),
            )
        }
    }

    /**
     * 更新 lwIP 原生核心狀態文字。
     */
    fun updateLwipStatus(status: String) {
        _snapshot.update { current ->
            current.copy(
                diagnostics = current.diagnostics.copy(lwipStatus = status),
            )
        }
    }

    /**
     * 更新本機 SOCKS5 Policy Relay 狀態與監聽埠號。
     */
    fun updateSocks5Status(port: Int, status: String) {
        _snapshot.update { current ->
            current.copy(
                diagnostics = current.diagnostics.copy(
                    socks5Port = port,
                    socks5Status = status,
                ),
            )
        }
    }

    /**
     * 記錄一筆新的 SOCKS5 Relay 連線建立。
     */
    fun recordSocks5ConnectionOpened(port: Int) {
        val total = socksTotalCounter.incrementAndGet()
        val active = socksActiveCounter.incrementAndGet()
        _snapshot.update { current ->
            current.copy(
                diagnostics = current.diagnostics.copy(
                    socks5Port = port,
                    socks5TotalConnections = total,
                    socks5ActiveConnections = active,
                    socks5Status = "監聽 127.0.0.1:$port（累計 $total / 活躍 $active）",
                ),
            )
        }
    }

    /**
     * 記錄一筆 SOCKS5 Relay 連線結束。
     */
    fun recordSocks5ConnectionClosed(port: Int) {
        val active = socksActiveCounter.updateAndGet { (it - 1).coerceAtLeast(0) }
        val total = socksTotalCounter.get()
        _snapshot.update { current ->
            val currentStatus = if (current.isRunning && port > 0) {
                "監聽 127.0.0.1:$port（累計 $total / 活躍 $active）"
            } else {
                current.diagnostics.socks5Status
            }
            current.copy(
                diagnostics = current.diagnostics.copy(
                    socks5ActiveConnections = active,
                    socks5Status = currentStatus,
                ),
            )
        }
    }

    /**
     * 記錄真實例外類別與錯誤訊息，供引擎診斷卡片呈現（絕不靜默吞掉錯誤）。
     */
    fun recordError(source: String, throwable: Throwable) {
        val detail = "${throwable::class.java.simpleName}: ${throwable.message ?: "無詳細訊息"}"
        recordErrorMessage("[$source] $detail")
    }

    /**
     * 記錄純文字診斷錯誤訊息。
     */
    fun recordErrorMessage(message: String) {
        _snapshot.update { current ->
            current.copy(
                diagnostics = current.diagnostics.copy(lastError = message),
            )
        }
    }

    /**
     * 寫入單筆放行或攔截流量紀錄並累加計數器。
     */
    fun recordTraffic(
        uid: Int,
        appName: String,
        packageName: String?,
        protocol: String,
        domain: String?,
        destinationIp: String,
        destinationPort: Int,
        action: TrafficAction,
        reason: BlockReason? = null,
    ) {
        val entry = TrafficLogEntry(
            id = nextId.getAndIncrement(),
            timestampMs = System.currentTimeMillis(),
            uid = uid,
            appName = appName,
            packageName = packageName,
            protocol = protocol,
            domain = domain,
            destinationIp = destinationIp,
            destinationPort = destinationPort,
            action = action,
            reason = reason,
        )
        _snapshot.update { current ->
            val updatedLogs = ArrayList<TrafficLogEntry>(
                (current.logs.size + 1).coerceAtMost(MAX_LOG_ENTRIES),
            )
            updatedLogs.add(entry)
            val keepCount = (MAX_LOG_ENTRIES - 1).coerceAtMost(current.logs.size)
            for (i in 0 until keepCount) {
                updatedLogs.add(current.logs[i])
            }
            current.copy(
                allowedCount = if (action == TrafficAction.ALLOWED) current.allowedCount + 1 else current.allowedCount,
                blockedCount = if (action == TrafficAction.BLOCKED) current.blockedCount + 1 else current.blockedCount,
                logs = updatedLogs,
            )
        }
    }

    /**
     * 清空即時日誌清單與統計計數器。
     */
    fun clearLogsAndCounters() {
        _snapshot.update { current ->
            current.copy(
                allowedCount = 0L,
                blockedCount = 0L,
                logs = emptyList(),
            )
        }
    }
}
