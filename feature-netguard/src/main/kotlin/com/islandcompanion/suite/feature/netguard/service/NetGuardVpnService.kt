package com.islandcompanion.suite.feature.netguard.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.islandcompanion.suite.core.rules.DataStoreNetGuardRulesRepository
import com.islandcompanion.suite.core.rules.DomainBlocklistEngine
import com.islandcompanion.suite.core.rules.NetGuardConfig
import com.islandcompanion.suite.feature.netguard.engine.EncryptedDnsResolver
import com.islandcompanion.suite.feature.netguard.engine.LocalPolicySocks5Server
import com.islandcompanion.suite.feature.netguard.engine.NetGuardRuntimeState
import com.islandcompanion.suite.feature.netguard.engine.TunPacketSentinel
import com.islandcompanion.suite.feature.netguard.engine.UidAppResolver
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.util.concurrent.Executors

/**
 * 本機網路守門員前景 [VpnService]。
 *
 * - 明確呼叫 `builder.setBlocking(true)` 確保 TUN fd 正常阻塞讀取，絕不因 `EAGAIN` 提前中止讀取執行緒。
 * - 透過 `addDisallowedApplication(packageName)` 與對外 Socket/DatagramSocket `protect()` 雙重防止 VPN 路由迴圈。
 * - 啟動與停止統一排程於背景單執行緒（避免阻塞主執行緒）；若原生庫載入或 lwIP 初始化失敗，
 *   立即關閉 TUN 並回報真實例外至 UI，絕不留下斷網空殼 VPN。
 */
class NetGuardVpnService : VpnService() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val lifecycleExecutor = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "NetGuard-Lifecycle").apply { isDaemon = true }
    }
    private val blocklistEngine = DomainBlocklistEngine()

    @Volatile
    private var currentConfig: NetGuardConfig = NetGuardConfig()

    private var tunInterface: ParcelFileDescriptor? = null
    private var localSocks5Server: LocalPolicySocks5Server? = null
    private var packetSentinel: TunPacketSentinel? = null
    private var healthMonitorJob: Job? = null
    private var rulesObservingStarted = false

    override fun onCreate() {
        super.onCreate()
        ensureNotificationChannel()
        startObservingRules()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                lifecycleExecutor.execute {
                    stopVpnTunnelLocked(statusMessage = "已停止")
                    stopSelf()
                }
                return START_NOT_STICKY
            }

            else -> {
                // 必須在 onStartCommand 同步呼叫 startForeground，避免 Android 12+ ForegroundServiceDidNotStartInTimeException
                val initial = NetGuardRuntimeState.snapshot.value
                promoteToForeground(initial.allowedCount, initial.blockedCount)
                lifecycleExecutor.execute {
                    startVpnTunnelLocked()
                }
                return START_STICKY
            }
        }
    }

    override fun onRevoke() {
        lifecycleExecutor.execute {
            stopVpnTunnelLocked(statusMessage = "系統已撤銷 VPN 授權")
            stopSelf()
        }
        super.onRevoke()
    }

    override fun onDestroy() {
        lifecycleExecutor.execute {
            stopVpnTunnelLocked(statusMessage = "已停止")
        }
        lifecycleExecutor.shutdown()
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun startObservingRules() {
        if (rulesObservingStarted) return
        rulesObservingStarted = true
        val repository = DataStoreNetGuardRulesRepository(applicationContext)

        serviceScope.launch {
            repository.config.collect { config ->
                currentConfig = config
            }
        }
        serviceScope.launch {
            repository.blockedDomains.collect { domains ->
                blocklistEngine.replaceAll(domains)
            }
        }
        serviceScope.launch {
            var lastAllowed = -1L
            var lastBlocked = -1L
            var lastRunning = false
            NetGuardRuntimeState.snapshot.collect { snap ->
                if (!snap.isRunning) {
                    lastRunning = false
                    return@collect
                }
                if (!lastRunning || snap.allowedCount != lastAllowed || snap.blockedCount != lastBlocked) {
                    lastRunning = true
                    lastAllowed = snap.allowedCount
                    lastBlocked = snap.blockedCount
                    updateForegroundNotification(snap.allowedCount, snap.blockedCount)
                    delay(NOTIFICATION_THROTTLE_MS)
                }
            }
        }
    }

    private fun startVpnTunnelLocked() {
        if (tunInterface != null) return

        NetGuardRuntimeState.resetSessionDiagnostics()

        // 1. 先驗證原生庫可正常載入，載入失敗時根本不建立 TUN 介面，避免斷網
        try {
            System.loadLibrary("hev-socks5-tunnel")
        } catch (t: Throwable) {
            NetGuardRuntimeState.updateLwipStatus("載入失敗：${t::class.java.simpleName}")
            NetGuardRuntimeState.recordError("NativeLoad", t)
            NetGuardRuntimeState.setRunning(false, "原生引擎載入失敗，已中止啟動")
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        // 2. 啟動本機 127.0.0.1 SOCKS5 Policy Relay
        val uidAppResolver = UidAppResolver(applicationContext)
        val dnsResolver = EncryptedDnsResolver(protectSocket = { socket -> protect(socket) })
        val socksServer = LocalPolicySocks5Server(
            configProvider = { currentConfig },
            blocklistEngine = blocklistEngine,
            lookupAppForTarget = { host, port ->
                val uid = uidAppResolver.findRecentUidForDestination(host, port)
                uidAppResolver.resolveApp(uid)
            },
            protectSocket = { socket -> protect(socket) },
            protectDatagramSocket = { dgram -> protect(dgram) },
        )

        val socksPort = try {
            socksServer.start()
        } catch (t: Throwable) {
            NetGuardRuntimeState.updateSocks5Status(0, "啟動失敗：${t::class.java.simpleName}")
            NetGuardRuntimeState.recordError("Socks5Start", t)
            NetGuardRuntimeState.setRunning(false, "本機策略代理啟動失敗，已中止啟動")
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }
        localSocks5Server = socksServer

        // 3. 建立 VPN TUN 介面（關鍵：setBlocking(true) + addDisallowedApplication(packageName)）
        val established = try {
            val builder = Builder()
                .setSession("Island Companion NetGuard")
                .setMtu(TunPacketSentinel.TUN_MTU)
                .setBlocking(true)
                .addAddress(TunPacketSentinel.TUN_IPV4_ADDR, 30)
                .addAddress(TunPacketSentinel.TUN_IPV6_ADDR, 128)
                .addRoute("0.0.0.0", 0)
                .addRoute("::", 0)
                .addDnsServer(TunPacketSentinel.TUN_DNS_IPV4_ADDR)
                // 防路由迴圈：將本 App 自身排除於 VPN 路由之外，搭配 protect() 雙重保護
                .addDisallowedApplication(packageName)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false)
            }
            builder.establish()
        } catch (t: Throwable) {
            NetGuardRuntimeState.recordError("VpnEstablish", t)
            stopVpnTunnelLocked(statusMessage = "建立 VPN 介面失敗：${t.message}")
            stopSelf()
            return
        }

        if (established == null) {
            NetGuardRuntimeState.recordErrorMessage("[VpnEstablish] Builder.establish() 回傳 null（未取得系統 VPN 授權）")
            stopVpnTunnelLocked(statusMessage = "建立 VPN 介面失敗（請確認已授予 VPN 權限）")
            stopSelf()
            return
        }
        tunInterface = established

        // 4. 啟動前哨層 + Os.socketpair + hev-socks5-tunnel（lwIP 核心）
        val sentinel = TunPacketSentinel(
            cacheDir = cacheDir,
            tunInterface = established,
            localSocks5Port = socksPort,
            configProvider = { currentConfig },
            blocklistEngine = blocklistEngine,
            uidAppResolver = uidAppResolver,
            dnsResolver = dnsResolver,
        )

        try {
            sentinel.start()
        } catch (t: Throwable) {
            NetGuardRuntimeState.updateLwipStatus("啟動失敗：${t::class.java.simpleName}")
            NetGuardRuntimeState.recordError("SentinelStart", t)
            stopVpnTunnelLocked(statusMessage = "引擎啟動失敗，已自動關閉 VPN 避免斷網")
            stopSelf()
            return
        }

        packetSentinel = sentinel
        NetGuardRuntimeState.setRunning(true, "本機網路守門員運行中（IP + DNS + TLS SNI）")

        // 5. 啟動背景健康監控：定期回報 lwIP TX/RX 統計，若原生核心意外崩潰則自動關閉 VPN 恢復網路
        healthMonitorJob?.cancel()
        healthMonitorJob = serviceScope.launch {
            while (isActive && tunInterface != null) {
                delay(HEALTH_POLL_INTERVAL_MS)
                val activeSentinel = packetSentinel ?: break
                val alive = activeSentinel.pollNativeHealth()
                if (!alive) {
                    lifecycleExecutor.execute {
                        stopVpnTunnelLocked(statusMessage = "lwIP 核心異常終止，已自動關閉 VPN 恢復連線")
                        stopSelf()
                    }
                    break
                }
            }
        }
    }

    private fun stopVpnTunnelLocked(statusMessage: String) {
        healthMonitorJob?.cancel()
        healthMonitorJob = null
        packetSentinel?.stop()
        packetSentinel = null
        localSocks5Server?.stop()
        localSocks5Server = null
        runCatching { tunInterface?.close() }
        tunInterface = null
        if (NetGuardRuntimeState.snapshot.value.diagnostics.lwipStatus.startsWith("運行中")) {
            NetGuardRuntimeState.updateLwipStatus("已停止")
        }
        NetGuardRuntimeState.setRunning(false, statusMessage)
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    private fun promoteToForeground(allowed: Long, blocked: Long) {
        val notification = buildStatusNotification(allowed = allowed, blocked = blocked)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun ensureNotificationChannel() {
        val manager = getSystemService(NotificationManager::class.java) ?: return
        val channel = NotificationChannel(
            CHANNEL_ID,
            "網路守門員狀態",
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = "顯示本機 VPN 守門員運行狀態與即時連線／攔截計數"
            setShowBadge(false)
        }
        manager.createNotificationChannel(channel)
    }

    private fun updateForegroundNotification(allowed: Long, blocked: Long) {
        val manager = getSystemService(NotificationManager::class.java) ?: return
        manager.notify(NOTIFICATION_ID, buildStatusNotification(allowed, blocked))
    }

    private fun buildStatusNotification(allowed: Long, blocked: Long): Notification {
        val stopIntent = Intent(this, NetGuardVpnService::class.java).apply {
            action = ACTION_STOP
        }
        val stopPendingIntent = PendingIntent.getService(
            this,
            1,
            stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val launchIntent = packageManager.getLaunchIntentForPackage(packageName)
        val contentPendingIntent = launchIntent?.let {
            PendingIntent.getActivity(
                this,
                0,
                it,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
        }

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("Island 網路守門員運行中")
            .setContentText("已放行：$allowed  •  已攔截：$blocked")
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(contentPendingIntent)
            .addAction(0, "停止守門員", stopPendingIntent)
            .build()
    }

    companion object {
        const val ACTION_START = "com.islandcompanion.suite.netguard.ACTION_START"
        const val ACTION_STOP = "com.islandcompanion.suite.netguard.ACTION_STOP"

        private const val CHANNEL_ID = "netguard_status_channel"
        private const val NOTIFICATION_ID = 1001
        private const val NOTIFICATION_THROTTLE_MS = 1_500L
        private const val HEALTH_POLL_INTERVAL_MS = 2_000L

        /**
         * 啟動本機網路守門員前景服務。呼叫前應先透過 `VpnService.prepare(context)` 確認授權。
         */
        fun startService(context: Context) {
            val intent = Intent(context, NetGuardVpnService::class.java).apply {
                action = ACTION_START
            }
            context.startForegroundService(intent)
        }

        /**
         * 停止本機網路守門員服務。
         */
        fun stopService(context: Context) {
            val intent = Intent(context, NetGuardVpnService::class.java).apply {
                action = ACTION_STOP
            }
            context.startService(intent)
        }
    }
}
