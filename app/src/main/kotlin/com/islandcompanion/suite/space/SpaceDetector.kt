package com.islandcompanion.suite.space

import android.app.admin.DevicePolicyManager
import android.content.Context
import com.islandcompanion.suite.core.rules.ExecutionSpace
import com.islandcompanion.suite.core.rules.SpaceOverrideMode

/**
 * 抽象化裝置管理員查詢介面，方便單元測試並隔離 Android Framework 依賴。
 */
interface ProfileOwnerInspector {
    /**
     * 回傳目前使用者空間中所有作用中的裝置管理員套件名稱。
     */
    fun getActiveAdminPackages(): List<String>

    /**
     * 檢查指定套件是否為目前使用者空間的 Profile Owner（例如 Island / Insular / Work Profile 管理者）。
     */
    fun isProfileOwnerApp(packageName: String): Boolean
}

/**
 * 使用 Android 公開且免特權的 [DevicePolicyManager.getActiveAdmins] 與
 * [DevicePolicyManager.isProfileOwnerApp] 實作空間檢查。
 *
 * 嚴格避免呼叫會觸發 [SecurityException] 的 `UserManager.isManagedProfile()`。
 */
class AndroidProfileOwnerInspector(
    context: Context,
) : ProfileOwnerInspector {
    private val devicePolicyManager: DevicePolicyManager? =
        context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager

    override fun getActiveAdminPackages(): List<String> {
        val dpm = devicePolicyManager ?: return emptyList()
        return runCatching {
            dpm.activeAdmins.orEmpty().map { it.packageName }.distinct()
        }.getOrDefault(emptyList())
    }

    override fun isProfileOwnerApp(packageName: String): Boolean {
        val dpm = devicePolicyManager ?: return false
        return runCatching {
            dpm.isProfileOwnerApp(packageName)
        }.getOrDefault(false)
    }
}

/**
 * 空間偵測結果，包含系統自動偵測結果與（若偵測到工作設定檔）對應的 Profile Owner 套件名稱。
 */
data class SpaceDetectionResult(
    val detectedSpace: ExecutionSpace,
    val profileOwnerPackage: String? = null,
)

/**
 * 執行空間偵測器：判斷目前 App 執行於主空間（Mainland）或工作設定檔（Island / Work Profile），
 * 並支援套用使用者在設定頁指定的手動覆寫角色模式。
 */
class SpaceDetector(
    private val inspector: ProfileOwnerInspector,
) {
    /**
     * 偵測目前所處的 Android 執行空間。
     * 若目前使用者空間內存在任何 `isProfileOwnerApp(...) == true` 的作用中管理員，
     * 則判定為 [ExecutionSpace.WORK_PROFILE]；否則安全回退至 [ExecutionSpace.MAINLAND]。
     */
    fun detect(): SpaceDetectionResult {
        val profileOwner = runCatching {
            inspector.getActiveAdminPackages()
                .firstOrNull { packageName -> inspector.isProfileOwnerApp(packageName) }
        }.getOrNull()

        return if (profileOwner != null) {
            SpaceDetectionResult(
                detectedSpace = ExecutionSpace.WORK_PROFILE,
                profileOwnerPackage = profileOwner,
            )
        } else {
            SpaceDetectionResult(
                detectedSpace = ExecutionSpace.MAINLAND,
                profileOwnerPackage = null,
            )
        }
    }

    /**
     * 依據自動偵測結果與手動覆寫設定，計算最終生效的執行空間角色。
     */
    fun resolveEffectiveSpace(
        detectedSpace: ExecutionSpace,
        overrideMode: SpaceOverrideMode,
    ): ExecutionSpace = when (overrideMode) {
        SpaceOverrideMode.AUTO -> detectedSpace
        SpaceOverrideMode.FORCE_MAINLAND -> ExecutionSpace.MAINLAND
        SpaceOverrideMode.FORCE_WORK_PROFILE -> ExecutionSpace.WORK_PROFILE
    }
}
