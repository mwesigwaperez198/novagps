package com.novara.agent.util

import android.content.Context
import android.content.SharedPreferences

object Config {
    private const val PREFS = "nova_agent"
    private const val KEY_SERVER = "server_url"
    private const val KEY_IDENTIFIER = "identifier"
    private const val KEY_REGISTERED = "registered"
    private const val KEY_FIREWALL = "firewall_on"
    private const val KEY_INTERVAL_MS = "interval_ms"

    private lateinit var prefs: SharedPreferences

    fun init(context: Context) {
        if (!::prefs.isInitialized) {
            prefs = context.applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        }
    }

    var serverUrl: String
        get() = runningPrefs().getString(KEY_SERVER, "http://127.0.0.1:8000").orEmpty().trimEnd('/')
        set(value) {
            runningPrefs().edit().putString(KEY_SERVER, value.trimEnd('/')).apply()
        }

    var identifier: String
        get() = runningPrefs().getString(KEY_IDENTIFIER, "").orEmpty()
        set(value) {
            runningPrefs().edit().putString(KEY_IDENTIFIER, value.trim()).apply()
        }

    var registered: Boolean
        get() = runningPrefs().getBoolean(KEY_REGISTERED, false)
        set(value) {
            runningPrefs().edit().putBoolean(KEY_REGISTERED, value).apply()
        }

    var firewallEnabled: Boolean
        get() = runningPrefs().getBoolean(KEY_FIREWALL, false)
        set(value) {
            runningPrefs().edit().putBoolean(KEY_FIREWALL, value).apply()
        }

    var reportIntervalMs: Long
        get() = runningPrefs().getLong(KEY_INTERVAL_MS, 30_000L)
        set(value) {
            runningPrefs().edit().putLong(KEY_INTERVAL_MS, value).apply()
        }

    private fun runningPrefs(): SharedPreferences {
        check(::prefs.isInitialized) { "Config.init() must be called first" }
        return prefs
    }
}