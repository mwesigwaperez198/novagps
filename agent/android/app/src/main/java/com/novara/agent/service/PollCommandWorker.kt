package com.novara.agent.service

import android.content.Context
import android.os.Build
import android.app.Notification
import androidx.core.app.NotificationCompat
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import com.novara.agent.NovaAgentApp
import com.novara.agent.R
import com.novara.agent.api.NovaApi
import com.novara.agent.util.Config
import java.util.concurrent.TimeUnit

/**
 * Server-command polling even while the foreground service is silent.
 * WorkManager survives process death, so a stolen device keeps checking in
 * for LOCK / LOST / WIPE on the regular schedule.
 */
class PollCommandWorker(
    context: Context,
    params: androidx.work.WorkerParameters,
) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        if (!Config.registered || Config.identifier.isEmpty()) return Result.success()
        runCatching {
            val pending = NovaApi.pullCommands(applicationContext)
            if (pending.isNotEmpty() && Build.VERSION.SDK_INT >= 31) {
                safetyNotice(applicationContext, pending.size)
            }
            for (cmd in pending) CommandWorker.execute(applicationContext, cmd)
        }
        return Result.success()
    }

    private fun safetyNotice(context: Context, count: Int) {
        val manager = context.getSystemService(android.app.NotificationManager::class.java)
        val notification = NotificationCompat.Builder(context, NovaAgentApp.CHANNEL_ID)
            .setContentTitle("NOVA")
            .setContentText("$count pending security command(s) received.")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setAutoCancel(true)
            .build()
        manager.notify(4043, notification)
    }

    companion object {
        private const val NAME = "nova.command.poll"

        fun schedule(context: Context) {
            val request = PeriodicWorkRequestBuilder<PollCommandWorker>(15, TimeUnit.MINUTES)
                .build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                NAME,
                ExistingPeriodicWorkPolicy.UPDATE,
                request,
            )
        }
    }
}