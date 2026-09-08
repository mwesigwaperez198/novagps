package com.novara.agent.bootstrap

import android.app.admin.DeviceAdminReceiver
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.widget.Toast
import com.novara.agent.R

/**
 * Device admin that becomes the *device owner* via
 *   adb shell dpm set-device-owner com.novara.agent/.bootstrap.DeviceOwnerAdmin
 *
 * Once device-owner, NOVA owns the device policy: the launcher icon
 * disappears, the user cannot uninstall or force-stop the agent, it
 * survives reboot, and remote lock/wipe/lost-mode behave at the OS level.
 */
class DeviceOwnerAdmin : DeviceAdminReceiver() {

    override fun onEnabled(context: Context, intent: Intent) {
        super.onEnabled(context, intent)
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val who = ComponentName(context, DeviceOwnerAdmin::class.java)
        if (dpm.isDeviceOwnerApp(context.packageName)) {
            // Best-effort boot protection on supported builds.
            runCatching {
                dpm.setMaximumFailedPasswordsForWipe(who, 10)
                dpm.setPasswordQuality(who, DevicePolicyManager.PASSWORD_QUALITY_SOMETHING)
                dpm.setCameraDisabled(who, false)
            }
            Toast.makeText(context, R.string.changelog, Toast.LENGTH_LONG).show()
        }
    }

    companion object {
        fun componentName(context: Context): ComponentName =
            ComponentName(context, DeviceOwnerAdmin::class.java)
    }
}