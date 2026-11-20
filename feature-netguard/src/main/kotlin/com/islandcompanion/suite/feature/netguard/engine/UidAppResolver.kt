package com.islandcompanion.suite.feature.netguard.engine

import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.os.Build
import android.os.Process
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap

/**
 * 連線來源應用程式的簡易識別資訊。
 */
data class AppIdentity(
    val uid: Int,
    val appName: String,
    val packageName: String?,
)

/**
 * 透過 Android 公開 API 將封包 5-tuple 對應至來源 UID 與應用程式名稱。
 *
 * 遵循最小權限原則：不申請 `QUERY_ALL_PACKAGES`，若因套件可見性限制無法解析名稱，
 * 則安全回退顯示 `UID <id>`。
 */
class UidAppResolver(
    context: Context,
) {
    private val packageManager: PackageManager = context.packageManager
    private val connectivityManager: ConnectivityManager? =
        context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager

    private val uidCache = ConcurrentHashMap<Int, AppIdentity>()
    private val recentTargetUidCache = ConcurrentHashMap<String, CachedUid>()

    /**
     * 依原始 IP 封包的 5-tuple 查詢連線所屬 UID（Android 10 / API 29+ 支援）。
     */
    fun lookupConnectionOwnerUid(
        protocol: Int,
        sourceIpBytes: ByteArray,
        sourcePort: Int,
        destinationIpBytes: ByteArray,
        destinationPort: Int,
    ): Int {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return Process.INVALID_UID
        val cm = connectivityManager ?: return Process.INVALID_UID
        return runCatching {
            val local = InetSocketAddress(InetAddress.getByAddress(sourceIpBytes), sourcePort)
            val remote = InetSocketAddress(InetAddress.getByAddress(destinationIpBytes), destinationPort)
            cm.getConnectionOwnerUid(protocol, local, remote)
        }.getOrDefault(Process.INVALID_UID)
    }

    /**
     * 記錄最近發起 TCP 連線的目標 `(dstIp:dstPort)` 與其 UID，供本機 SOCKS5 策略代理關聯來源 App。
     */
    fun rememberDestinationUid(destinationIp: String, destinationPort: Int, uid: Int) {
        if (uid <= 0) return
        val key = "$destinationIp:$destinationPort"
        recentTargetUidCache[key] = CachedUid(uid = uid, timestampMs = System.currentTimeMillis())
        if (recentTargetUidCache.size > MAX_TARGET_CACHE_SIZE) {
            pruneStaleTargets()
        }
    }

    /**
     * 查詢最近與目標 `(dstIp:dstPort)` 關聯的來源 UID。
     */
    fun findRecentUidForDestination(destinationIp: String, destinationPort: Int): Int {
        val key = "$destinationIp:$destinationPort"
        val cached = recentTargetUidCache[key] ?: return Process.INVALID_UID
        val ageMs = System.currentTimeMillis() - cached.timestampMs
        return if (ageMs <= TARGET_CACHE_TTL_MS) cached.uid else Process.INVALID_UID
    }

    /**
     * 將 UID 轉換為可讀的 App 名稱與套件名稱（帶記憶體快取）。
     */
    fun resolveApp(uid: Int): AppIdentity {
        if (uid <= 0) {
            return AppIdentity(uid = uid, appName = "未知來源", packageName = null)
        }
        return uidCache.getOrPut(uid) {
            if (uid == Process.SYSTEM_UID) {
                return@getOrPut AppIdentity(uid = uid, appName = "Android 系統", packageName = "android")
            }
            val packages = runCatching { packageManager.getPackagesForUid(uid) }.getOrNull()
            val primaryPkg = packages?.firstOrNull()
            if (primaryPkg == null) {
                return@getOrPut AppIdentity(uid = uid, appName = "UID $uid", packageName = null)
            }
            val label = runCatching {
                val appInfo = packageManager.getApplicationInfo(primaryPkg, 0)
                packageManager.getApplicationLabel(appInfo).toString()
            }.getOrDefault(primaryPkg)
            AppIdentity(uid = uid, appName = label, packageName = primaryPkg)
        }
    }

    private fun pruneStaleTargets() {
        val now = System.currentTimeMillis()
        recentTargetUidCache.entries.removeIf { (_, value) ->
            now - value.timestampMs > TARGET_CACHE_TTL_MS
        }
    }

    private data class CachedUid(
        val uid: Int,
        val timestampMs: Long,
    )

    private companion object {
        const val MAX_TARGET_CACHE_SIZE = 512
        const val TARGET_CACHE_TTL_MS = 15_000L
    }
}
