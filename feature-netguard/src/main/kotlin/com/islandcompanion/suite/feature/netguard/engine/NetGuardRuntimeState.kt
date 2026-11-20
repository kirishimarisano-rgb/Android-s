package com.islandcompanion.suite.feature.netguard.engine

import com.islandcompanion.suite.core.rules.BlockReason
import com.islandcompanion.suite.core.rules.TrafficAction
import com.islandcompanion.suite.core.rules.TrafficLogEntry
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import java.util.concurrent.atomic.AtomicLong

/**
 * 本機網路守門員的即時執行期狀態快照。
 */
data class NetGuardRuntimeSnapshot(
    val isRunning: Boolean = false,
    val allowedCount: Long = 0L,
    val blockedCount: Long = 0L,
    val statusMessage: String = "尚未啟動",
    val logs: List<TrafficLogEntry> = emptyList(),
)

/**
 * 執行期共享狀態匯流排（單向資料流），供 [NetGuardVpnService] 寫入統計與日誌，
 * 並讓 Compose UI 與前景通知即時訂閱。所有資料僅存於本機記憶體。
 */
object NetGuardRuntimeState {
    private const val MAX_LOG_ENTRIES = 200
    private val nextId = AtomicLong(1L)

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
