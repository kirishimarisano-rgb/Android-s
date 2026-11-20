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
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * 本機網路守門員前景 [VpnService]。
 *
 * - 透過 `addDisallowedApplication(packageName)` 與對外連線 `protect()` 徹底防止 VPN 路由迴圈。
 * - 透過 [TunPacketSentinel] + `hev-socks5-tunnel`（lwIP）+ [LocalPolicySocks5Server] 實現
 *   IP + DNS + TLS SNI 層級過濾（絕不進行 HTTPS MITM 解密）。
 * - 常駐前景通知即時顯示放行與攔截計數，並提供一鍵停止操作。
 */
class NetGuardVpnService : VpnService() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val blocklistEngine = DomainBlocklistEngine()

    @Volatile
    private var currentConfig: NetGuardConfig = NetGuardConfig()

    private var tunInterface: ParcelFileDescriptor? = null
    private var localSocks5Server: LocalPolicySocks5Server? = null
    private var packetSentinel: TunPacketSentinel? = null
    private var rulesObservingStarted = false

    override fun onCreate() {
        super.onCreate()
        ensureNotificationChannel()
        startObservingRules()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopVpnTunnel()
                stopSelf()
                return START_NOT_STICKY
            }

            else -> {
                startVpnTunnel()
                return START_STICKY
            }
        }
    }

    override fun onRevoke() {
        stopVpnTunnel()
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopVpnTunnel()
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

    private fun startVpnTunnel() {
        if (tunInterface != null) return

        val initialSnapshot = NetGuardRuntimeState.snapshot.value
        val notification = buildStatusNotification(
            allowed = initialSnapshot.allowedCount,
            blocked = initialSnapshot.blockedCount,
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }

        val established = runCatching {
            val builder = Builder()
                .setSession("Island Companion NetGuard")
                .setMtu(TunPacketSentinel.TUN_MTU)
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
        }.getOrNull()

        if (established == null) {
            NetGuardRuntimeState.setRunning(false, "建立 VPN 介面失敗（請確認已授予 VPN 權限）")
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }

        tunInterface = established

        val uidAppResolver = UidAppResolver(applicationContext)
        val dnsResolver = EncryptedDnsResolver(protectSocket = { socket -> protect(socket) })
        val socksServer = LocalPolicySocks5Server(
            configProvider = { currentConfig },
            blocklistEngine = blocklistEngine,
            uidAppResolver = uidAppResolver,
            protectSocket = { socket -> protect(socket) },
        )

        val socksPort = runCatching { socksServer.start() }.getOrElse {
            stopVpnTunnel()
            NetGuardRuntimeState.setRunning(false, "本機策略代理啟動失敗：${it.message}")
            stopSelf()
            return
        }
        localSocks5Server = socksServer

        val sentinel = TunPacketSentinel(
            cacheDir = cacheDir,
            tunInterface = established,
            localSocks5Port = socksPort,
            configProvider = { currentConfig },
            blocklistEngine = blocklistEngine,
            uidAppResolver = uidAppResolver,
            dnsResolver = dnsResolver,
        )

        runCatching { sentinel.start() }.onFailure { err ->
            stopVpnTunnel()
            NetGuardRuntimeState.setRunning(false, "lwIP 核心啟動失敗：${err.message}")
            stopSelf()
            return
        }
        packetSentinel = sentinel
        NetGuardRuntimeState.setRunning(true, "本機網路守門員運行中（IP + DNS + TLS SNI）")
    }

    private fun stopVpnTunnel() {
        packetSentinel?.stop()
        packetSentinel = null
        localSocks5Server?.stop()
        localSocks5Server = null
        runCatching { tunInterface?.close() }
        tunInterface = null
        NetGuardRuntimeState.setRunning(false, "已停止")
        stopForeground(STOP_FOREGROUND_REMOVE)
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
