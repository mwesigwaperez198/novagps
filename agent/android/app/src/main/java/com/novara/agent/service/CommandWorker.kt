package com.novara.agent.service

import android.app.admin.DevicePolicyManager
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import androidx.core.app.NotificationCompat
import com.novara.agent.MainActivity
import com.novara.agent.NovaAgentApp
import com.novara.agent.api.NovaApi
import com.novara.agent.api.RemoteCommand
import com.novara.agent.bootstrap.DeviceOwnerAdmin
import com.novara.agent.util.Config

/**
 * Pulls pending commands from the NOVA server for this device and executes
 * them: locate, lock, lost-mode, message, wipe. Runs on every location
 * report and on a WorkManager schedule.
 */
object CommandWorker {

    private val processed = HashSet<String>()

    fun tick(context: Context) {
        if (!Config.registered || Config.identifier.isEmpty()) return
        val commands = runCatching { NovaApi.pullCommands(context) }.getOrNull() ?: return
        for (command in commands) execute(context, command)
    }

    private fun execute(context: Context, command: RemoteCommand) {
        if (!processed.add(command.command_id)) return
        val payload = command.payload
        when (command.command_type) {
            "locate" -> reportNow(context)
            "lock" -> lock(context, payload["message"]?.toString().orEmpty())
            "lost" -> {
                lostMode(context, payload)
                lock(context, payload["message"]?.toString().orEmpty())
            }
            "message" -> notify(context, payload["message"]?.toString() ?: "NOVA message", false)
            "wipe" -> wipe(context, payload)
        }
        runCatching { NovaApi.ackCommand(context, command.command_id) }
    }

    // Locate: snapshot whatever fix the service is carrying and upload it.
    private fun reportNow(context: Context) {
        val lm = context.getSystemService(Context.LOCATION_SERVICE) as android.location.LocationManager
        val fix = runCatching {
            lm.getLastKnownLocation(android.location.LocationManager.GPS_PROVIDER)
                ?: lm.getLastKnownLocation(android.location.LocationManager.NETWORK_PROVIDER)
        }.getOrNull() ?: return
        AgentService.pushNow(context, fix)
    }

    private fun admin(context: Context): Pair<DevicePolicyManager, ComponentName>? {
        val who = DeviceOwnerAdmin.componentName(context)
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        return if (dpm.isAdminActive(who)) dpm to who else null
    }

    private fun lock(context: Context, message: String) {
        val pair = admin(context) ?: run { notify(context, if (message.isEmpty()) "Remote lock requested (admin not active)." else message, true); return }
        pair.first.lockNow()
        notify(context, if (message.isEmpty()) "This device has been remotely locked." else message, true)
    }

    private fun lostMode(context: Context, payload: Map<String, Any>) {
        val message = payload["message"]?.toString()
            ?: "This device is lost. Please return it to its owner."
        val interval = (payload["location_interval"]?.toString()?.toLongOrNull() ?: 30L) * 1000
        if (interval >= 10_000) Config.reportIntervalMs = interval
        notify(context, message, true)
    }

    private fun wipe(context: Context, payload: Map<String, Any>) {
        val expected = payload["confirm_code"]?.toString().orEmpty()
        val provided = payload["confirm_code"]?.toString().orEmpty()
        if (expected.isNotEmpty() && expected != provided) {
            notify(context, "Wipe rejected: confirm code mismatch.", true)
            return
        }
        val pair = admin(context)
        if (pair == null) {
            notify(context, "Wipe requested but device admin is not active.", true)
            return
        }
        pair.first.wipeData(DevicePolicyManager.WIPE_RESET_PROTECTION_DATA or
            DevicePolicyManager.WIPE_EXTERNAL_STORAGE)
    }

    private fun notify(context: Context, text: String, loud: Boolean) {
        val open = PendingIntent.getActivity(
            context, 0, Intent(context, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = NotificationCompat.Builder(context, NovaAgentApp.CHANNEL_ID)
            .setContentTitle("NOVA")
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentIntent(open)
            .setAutoCancel(!loud)
            .setOngoing(loud)
            .setPriority(if (loud) NotificationCompat.PRIORITY_HIGH else NotificationCompat.PRIORITY_DEFAULT)
            .build()
        context.getSystemService(NotificationManager::class.java).notify(4022, notification)
    }
}