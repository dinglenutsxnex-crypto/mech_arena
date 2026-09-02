package com.nexora.hammerscale.sfa

import android.content.Context
import android.util.Log
import org.json.JSONObject

/**
 * SFA BattleConfig — independent copy for SFA chronicle.
 * Loads sfa_battles.json from assets (generated from archive/scripts/battles.js).
 * Maps chronicle/battle ID -> roundsToWin, auto-detects via roguelike_enter_chapter and process_offline_batch.
 */
object SfaBattleConfig {
    private val map = mutableMapOf<String, Int>()
    @Volatile var loadedVersion: String = ""
        private set
    @Volatile var isLoaded: Boolean = false
        private set

    fun roundsFor(battleId: String): Int? = map[battleId]

    fun load(context: Context) {
        try {
            val txt = context.assets.open("sfa_battles.json").bufferedReader().readText()
            val root = JSONObject(txt)
            loadedVersion = root.optString("version", "")
            val battles = root.optJSONObject("battles") ?: JSONObject()
            val keys = battles.keys()
            while (keys.hasNext()) {
                val k = keys.next()
                val v = battles.optInt(k, 2)
                map[k] = v
            }
            isLoaded = true
            Log.d("SfaBattleConfig", "Loaded ${map.size} SFA battles v=$loadedVersion")
        } catch (e: Exception) {
            Log.w("SfaBattleConfig", "Failed load: ${e.message}")
            // fallback defaults
            map["1"] = 1
            map["40"] = 2
            isLoaded = true
        }
    }

    fun ensureLoaded(context: Context) {
        if (!isLoaded) load(context)
    }
}
