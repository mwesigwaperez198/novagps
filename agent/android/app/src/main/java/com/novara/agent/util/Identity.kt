package com.novara.agent.util

import android.content.Context
import android.net.ConnectivityManager
import android.os.Build
import android.os.Environment
import android.telephony.TelephonyManager
import java.io.File
import java.net.Inet4Address
import java.net.NetworkInterface
import java.security.MessageDigest
import java.util.UUID
import kotlin.math.max

object Identity {

    fun stableIdentifier(context: Context): String {
        val saved = Config.identifier
        if (saved.isNotEmpty()) return saved
        // Fall back to a per-install random id when the dashboard id has not
        // been pasted yet; survives process deaths via shared preferences.
        val prefs = context.applicationContext.getSharedPreferences("nova_identity", Context.MODE_PRIVATE)
        var id = prefs.getString("device_id", null)
        if (id == null) {
            id = UUID.randomUUID().toString()
            prefs.edit().putString("device_id", id).apply()
        }
        return id
    }

    fun firmware(): Map<String, String> = buildMap {
        put("manufacturer", Build.MANUFACTURER)
        put("model", Build.MODEL)
        put("os_type", "android")
        put("os_version", Build.VERSION.RELEASE)
        put("build", Build.DISPLAY)
        put("sdk", Build.VERSION.SDK_INT.toString())
        put("board", Build.BOARD)
        put("hardware", Build.HARDWARE)
        put("fingerprint", Build.FINGERPRINT)
    }

    fun batteryPercent(context: Context): Int? {
        val running = context.registerReceiver(null, android.content.IntentFilter(
            android.content.Intent.ACTION_BATTERY_CHANGED,
        ))
        val level = running?.getIntExtra(android.os.BatteryManager.EXTRA_LEVEL, -1) ?: -1
        val scale = running?.getIntExtra(android.os.BatteryManager.EXTRA_SCALE, -1) ?: -1
        return if (level >= 0 && scale > 0) {
            (level * 100 / scale)
        } else null
    }

    fun networkType(context: Context): String {
        val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
        return when (tm?.dataNetworkType) {
            TelephonyManager.NETWORK_TYPE_LTE -> "lte"
            TelephonyManager.NETWORK_TYPE_NR -> "5g"
            TelephonyManager.NETWORK_TYPE_HSDPA,
            TelephonyManager.NETWORK_TYPE_HSPAP,
            TelephonyManager.NETWORK_TYPE_HSUPA,
            -> "3g"
            TelephonyManager.NETWORK_TYPE_GPRS,
            TelephonyManager.NETWORK_TYPE_EDGE,
            -> "2g"
            else -> "wifi"
        }
    }

    fun localIp(context: Context): String? {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        val active = cm?.activeNetwork ?: return null
        val caps = cm.getNetworkCapabilities(active) ?: return null
        val names = if (caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_CELLULAR)) {
            listOf("rmnet", "ccmni", "wwan", "pdp")
        } else {
            listOf("wlan", "eth", "en0")
        }
        return try {
            val interfaces = NetworkInterface.getNetworkInterfaces() ?: return null
            for (networkInterface in interfaces) {
                if (networkInterface.isLoopback || !networkInterface.isUp) continue
                if (names.none { networkInterface.name.startsWith(it) }) continue
                val addresses = networkInterface.inetAddresses ?: continue
                for (address in addresses) {
                    if (!address.isLoopbackAddress && address is Inet4Address) {
                        return address.hostAddress
                    }
                }
            }
            null
        } catch (_: Exception) {
            null
        }
    }

    fun carrierName(context: Context): String? {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        val active = cm?.activeNetwork ?: return null
        val caps = cm.getNetworkCapabilities(active) ?: return null
        if (!caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_CELLULAR)) return null
        val tm = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
        val name = runCatching { tm?.networkOperatorName }.getOrNull()
        return name?.takeIf { it.isNotBlank() }
    }

    fun storageInfo(): Map<String, Any> = buildMap {
        val stat = android.os.StatFs(Environment.getDataDirectory().path)
        val totalBytes = stat.totalBytes
        val freeBytes = stat.availableBytes
        put("total_bytes", totalBytes)
        put("free_bytes", freeBytes)
        put("used_pct", ((totalBytes - freeBytes) * 100 / max(1, totalBytes)))
    }

    fun sha256(value: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(value.toByteArray())
            .joinToString("") { "%02x".format(it) }
}