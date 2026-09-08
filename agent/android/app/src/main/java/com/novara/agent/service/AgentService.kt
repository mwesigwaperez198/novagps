package com.novara.agent.service

import android.Manifest
import android.app.Notification
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.os.Build
import android.os.IBinder
import android.os.Looper
import androidx.core.app.NotificationCompat
import com.novara.agent.MainActivity
import com.novara.agent.NovaAgentApp
import com.novara.agent.R
import com.novara.agent.api.LocationUpdate
import com.novara.agent.api.NovaApi
import com.novara.agent.util.Config
import com.novara.agent.util.Identity
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * Foreground service that keeps a fresh GPS fix and streams it to
 * POST /update-location. Runs while the agent is registered, survives
 * reboots (BootReceiver) and battery killers (device owner / ignore
 * battery optimizations).
 */
class AgentService : Service(), LocationListener {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private lateinit var locationManager: LocationManager
    private var lastKnown: Location? = null
    private var lastPingAt = 0L

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        locationManager = getSystemService(Context.LOCATION_SERVICE) as LocationManager
        startForeground(NodeID, notification())
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Config.init(this)
        requestFixes()
        heartbeat()
        return START_STICKY
    }

    override fun onDestroy() {
        scope.cancel()
        runCatching { locationManager.removeUpdates(this) }
        super.onDestroy()
    }

    fun requestFixes() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            locationManager.requestLocationUpdates(
                LocationManager.GPS_PROVIDER,
                Config.reportIntervalMs, 0f, this, Looper.getMainLooper(),
            )
            locationManager.requestLocationUpdates(
                LocationManager.NETWORK_PROVIDER,
                Config.reportIntervalMs, 0f, this, Looper.getMainLooper(),
            )
        } else {
            @Suppress("DEPRECATION")
            locationManager.requestLocationUpdates(
                LocationManager.GPS_PROVIDER, Config.reportIntervalMs, 0f, this,
            )
            @Suppress("DEPRECATION")
            locationManager.requestLocationUpdates(
                LocationManager.NETWORK_PROVIDER, Config.reportIntervalMs, 0f, this,
            )
        }
        // Seed a fix immediately from cached provider values.
        lastKnown = bestCachedFix()
    }

    private fun bestCachedFix(): Location? {
        val gps = locationManager.getLastKnownLocation(LocationManager.GPS_PROVIDER)
        val net = locationManager.getLastKnownLocation(LocationManager.NETWORK_PROVIDER)
        return when {
            gps != null && net == null -> gps
            net != null && gps == null -> net
            gps != null && net != null ->
                if (gps.accuracy <= net.accuracy) gps else net
            else -> null
        }
    }

    override fun onLocationChanged(location: Location) {
        lastKnown = location
        pushLocation(location)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val now = System.currentTimeMillis()
            if (now - lastPingAt > 60_000L) {
                lastPingAt = now
                heartbeat()
            }
        }
    }

    private fun heartbeat() {
        // Heartbeats double as a "still alive" ping; the analytics endpoint
        // is server-side, so the ping IS the location report itself.
        lastKnown?.let { pushLocation(it) }
    }

    private fun pushLocation(location: Location) {
        if (!Config.registered || Config.identifier.isEmpty()) return
        scope.launch {
            runCatching {
                NovaApi.sendLocation(
                    this@AgentService,
                    LocationUpdate(
                        identifier = Config.identifier,
                        latitude = location.latitude,
                        longitude = location.longitude,
                        altitude = location.altitude,
                        speed = location.speed.toDouble(),
                        heading = location.bearing.toDouble(),
                        accuracy = location.accuracy.toDouble(),
                        source = "mobile",
                        raw_payload = mapOf(
                            "battery" to Identity.batteryPercent(this@AgentService),
                            "network" to Identity.networkType(this@AgentService),
                            "charging" to isCharging(),
                        ),
                    ),
                )
                CommandWorker.tick(this@AgentService)
            }
        }
    }

    private fun isCharging(): Boolean {
        val intent = applicationContext.registerReceiver(
            null,
            android.content.IntentFilter(android.content.Intent.ACTION_BATTERY_CHANGED),
        )
        val plugged = intent?.getIntExtra(android.os.BatteryManager.EXTRA_PLUGGED, -1) ?: -1
        return plugged != 0
    }

    private fun notification(): Notification {
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, NovaAgentApp.CHANNEL_ID)
            .setContentTitle("NOVA Agent")
            .setContentText("Location reporting active for this device.")
            .setSmallIcon(android.R.drawable.ic_menu_mylocation)
            .setContentIntent(open)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_MIN)
            .build()
    }

    companion object {
        private const val NodeID = 4041

        fun startForeground(context: Context) {
            val intent = Intent(context, AgentService::class.java)
            context.startForegroundService(intent)
        }

        fun pushNow(context: Context, location: Location) {
            if (!hasLocationPermission(context)) return
            runCatching {
                val lifecycle = Intent(context, AgentService::class.java)
                context.startService(lifecycle)
            }
            // Fall back to a direct push when the service is mid-restart.
            val gps = context.getSystemService(Context.LOCATION_SERVICE) as LocationManager
            val fix = location ?: gps.getLastKnownLocation(LocationManager.NETWORK_PROVIDER) ?: return
            CoroutineScope(SupervisorJob() + Dispatchers.IO).launch {
                runCatching {
                    NovaApi.sendLocation(
                        context,
                        LocationUpdate(
                            identifier = Config.identifier,
                            latitude = fix.latitude,
                            longitude = fix.longitude,
                            source = "mobile",
                        ),
                    )
                }
            }
        }

        fun hasLocationPermission(context: Context): Boolean =
            context.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) ==
                PackageManager.PERMISSION_GRANTED
    }
}