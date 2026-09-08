package com.novara.agent

import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.novara.agent.bootstrap.DeviceOwnerAdmin
import com.novara.agent.service.AgentService
import com.novara.agent.util.Config
import com.novara.agent.util.DeviceKeys
import com.novara.agent.util.NovaPayload
import java.io.File

/**
 * Receives a .nova file pushed by the USB flash tool (adb am start
 * -n ...ImportActivity --es file /sdcard/Download/device.nova).
 *
 * Gate sequence:
 *   1. NOVA Ed25519 signature must verify (else the file is inert).
 *   2. The device's X25519 key must unlock it (else it was meant for
 *      another device).
 *   3. AES-GCM + manifest SHA-256 must match (else it was tampered).
 *
 * On success the embedded payload is written to internal storage and the
 * location/reporting service starts; if we are device owner, the launcher
 * entry is disabled so the agent disappears from the app drawer.
 */
class ImportActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_import)
        Config.init(this)

        val path = intent?.getStringExtra("file")
        val result = findViewById<TextView>(R.id.importStatus)
        if (path.isNullOrEmpty()) {
            result.setText(R.string.import_need_file)
            return
        }
        val payload = File(path)
        if (!payload.exists()) {
            result.setText(R.string.import_missing)
            return
        }

        val opened = NovaPayload.open(
            data = payload.readBytes(),
            novaPubPem = NOVA_PUB_PEM,
            deviceX25519Key = DeviceKeys.privateKey(this),
        )
        if (opened == null) {
            result.setText(R.string.import_rejected)
            return
        }

        val target = File(filesDir, opened.name)
        target.writeBytes(opened.artifact)
        Config.registered = true
        AgentService.startForeground(this)
        hideFromLauncherIfOwner()
        result.text = getString(
            R.string.import_ok,
            "os=${opened.manifest["os"]}, arch=${opened.manifest["arch"]}",
        )
    }

    private fun hideFromLauncherIfOwner() {
        val dpm = getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        if (!dpm.isDeviceOwnerApp(packageName)) return
        val launcher = ComponentName(this, MainActivity::class.java)
        dpm.setComponentEnabledSetting(
            launcher,
            PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
            DevicePolicyManager.FLAG_OVERRIDE_EXEMPT_SIGNATURE,
        )
    }

    companion object {
        // Embed the company Ed25519 public key here (nova.pub from nova-pack
        // keygen). Only payloads signed by that key will ever be opened.
        val NOVA_PUB_PEM: String = """-----BEGIN PUBLIC KEY-----
            PLACEHOLDER_NOVA_ED25519_PUBLIC_KEY
            -----END PUBLIC KEY-----"""
    }
}

// Kept intentionally separate so the flash tool only ever talks to
// ImportActivity; MainActivity remains the first-boot config screen.
object ImportRoutes {
    const val ACTION = "nova.novara.agent.IMPORT"
}