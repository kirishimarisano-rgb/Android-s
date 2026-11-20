package com.islandcompanion.suite.space

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.islandcompanion.suite.core.rules.SpaceOverrideMode
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.spacePreferencesDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "space_preferences",
)

/**
 * 讀寫使用者手動覆寫執行空間模式設定的儲存介面（純本機儲存）。
 */
interface SpaceOverrideRepository {
    /**
     * 監聽目前儲存的手動覆寫模式，預設為 [SpaceOverrideMode.AUTO]。
     */
    val overrideMode: Flow<SpaceOverrideMode>

    /**
     * 更新並持久化手動覆寫模式。
     */
    suspend fun setOverrideMode(mode: SpaceOverrideMode)
}

/**
 * 基於 Jetpack Preferences DataStore 的本機設定儲存實作。
 */
class DataStoreSpaceOverrideRepository(
    context: Context,
) : SpaceOverrideRepository {
    private val dataStore = context.applicationContext.spacePreferencesDataStore

    override val overrideMode: Flow<SpaceOverrideMode> = dataStore.data.map { prefs ->
        val raw = prefs[KEY_OVERRIDE_MODE]
        SpaceOverrideMode.entries.firstOrNull { it.name == raw } ?: SpaceOverrideMode.AUTO
    }

    override suspend fun setOverrideMode(mode: SpaceOverrideMode) {
        dataStore.edit { prefs ->
            prefs[KEY_OVERRIDE_MODE] = mode.name
        }
    }

    private companion object {
        val KEY_OVERRIDE_MODE = stringPreferencesKey("space_override_mode")
    }
}
