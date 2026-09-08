package com.novara.agent

import android.annotation.SuppressLint
import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager

class NovaAgentApp : Application() {

    override fun onCreate() {
        super.onCreate()
        createChannels()
    }

    private fun createChannels() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.notification_channel_name),
            NotificationManager.IMPORTANCE_MIN,
        ).apply { description = getString(R.string.notification_channel_desc) }
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    companion object {
        const val CHANNEL_ID = "nova_agent"
        val PACKAGE: String = NovaAgentApp::class.java.getPackage()?.name ?: "com.novara.agent"

        @SuppressLint("StaticFieldLeak")
        @Volatile
        lateinit var instance: Application
            private set

        fun attach(app: Application) {
            instance = app
        }
    }
}