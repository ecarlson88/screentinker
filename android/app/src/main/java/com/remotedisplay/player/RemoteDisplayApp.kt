package com.remotedisplay.player

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build

class RemoteDisplayApp : Application() {

    companion object {
        const val CHANNEL_ID = "remote_display_service"
        const val CHANNEL_NAME = "SLI-Signs Service"
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                CHANNEL_NAME,
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "SLI-Signs background service"
                setShowBadge(false)
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }
}
