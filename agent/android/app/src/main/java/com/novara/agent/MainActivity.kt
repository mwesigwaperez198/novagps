package com.novara.agent

import android.Manifest
import android.app.admin.DevicePolicyManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import com.novara.agent.bootstrap.DeviceOwnerAdmin
import com.novara.agent.service.AgentService
import com.novara.agent.service.FirewallService
import com.novara.agent.service.PollCommandWorker
import com.novara.agent.util.Config
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val permissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { grants ->
            if (grants[Manifest.permission.ACCESS_FINE_LOCATION] == true) {
                saveAndStart()
            } else {
                Toast.makeText(this, "Location permission is required for NOVA tracking.", Toast.LENGTH_LONG).show()
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        Config.init(this)
        attachHandlers()
        PollCommandWorker.schedule(this)
        statusLine()
    }

    private fun attachHandlers() {
        findViewById<android.widget.EditText>(R.id.serverInput).setText(Config.serverUrl)
        findViewById<android.widget.EditText>(R.id.identifierInput).setText(Config.identifier)
        findViewById<android.widget.Button>(R.id.saveButton).setOnClickListener { onSave() }
        findViewById<android.widget.Button>(R.id.firewallButton).setOnClickListener { onFirewall() }
        findViewById<android.widget.TextView>(R.id.statusField).text =
            if (Config.registered) "Agent is active for ${Config.identifier}" else "Not yet registered"
    }

    private fun onSave() {
        Config.serverUrl = findViewById<android.widget.EditText>(R.id.serverInput).text.toString()
        Config.identifier = findViewById<android.widget.EditText>(R.id.identifierInput).text.toString()
        if (Config.serverUrl.isEmpty()) {
            Toast.makeText(this, "Enter the NOVA server URL first.", Toast.LENGTH_SHORT).show()
            return
        }
        if (Config.identifier.isEmpty()) {
            Toast.makeText(this, "Enter the device identifier from the dashboard.", Toast.LENGTH_SHORT).show()
            return
        }
        if (AgentService.hasLocationPermission(this)) {
            saveAndStart()
        } else {
            permissionLauncher.launch(arrayOf(
                Manifest.permission.ACCESS_FINE_LOCATION,
                Manifest.permission.ACCESS_COARSE_LOCATION,
            ))
        }
    }

    private fun saveAndStart() {
        scope.launch {
            val consented = withContext(Dispatchers.IO) { grantConsent() }
            withContext(Dispatchers.Main) {
                Config.registered = consented || Config.registered
                PollCommandWorker.schedule(this)
                AgentService.startForeground(this@MainActivity)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    val dpm = getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
                    val who = DeviceOwnerAdmin.componentName(this@MainActivity)
                    if (dpm.isDeviceOwnerApp(packageName)) {
                        runCatching { dpm.setAlwaysOnVpnLockdown(who, true) }
                        runCatching { dpm.setBatteryOptimizationExemptions(listOf(packageName)) }
                    }
                }
                statusLine()
                Toast.makeText(
                    this@MainActivity,
                    if (consented) "Agent running — location now reporting." else "Saved. Consent could not be created.",
                    Toast.LENGTH_LONG,
                ).show()
            }
        }
    }

    private suspend fun grantConsent(): Boolean {
        if (!Config.identifier.isNotEmpty()) return false
        return runCatching { com.novara.agent.api.NovaApi.grantConsent(Config.identifier) }
            .getOrDefault(false)
    }

    private fun onFirewall() {
        val prepared = VpnService.prepare(this)
        if (prepared != null) {
            startActivityForResult(prepared, REQUEST_VPN)
        } else {
            startProtection()
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_VPN) {
            if (resultCode == RESULT_OK) startProtection()
            else Toast.makeText(this, "Protection not enabled.", Toast.LENGTH_SHORT).show()
        }
    }

    private fun startProtection() {
        Config.firewallEnabled = true
        FirewallService.start(this)
        val dpm = getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager
        val who = DeviceOwnerAdmin.componentName(this)
        if (dpm.isDeviceOwnerApp(packageName)) {
            runCatching { dpm.setAlwaysOnVpnPackage(who, packageName, true) }
            runCatching { dpm.setAlwaysOnVpnLockdown(who, true) }
            Toast.makeText(this, "Protection active (always-on + lockdown).", Toast.LENGTH_SHORT).show()
        } else {
            Toast.makeText(this, "Protection active. Make this app device owner for lockdown mode.", Toast.LENGTH_LONG).show()
        }
    }

    private fun statusLine() {
        val status = findViewById<android.widget.TextView>(R.id.statusField)
        val owner = (getSystemService(Context.DEVICE_POLICY_SERVICE) as DevicePolicyManager)
            .isDeviceOwnerApp(packageName)
        status.text = if (Config.registered) {
            "Active for ${Config.identifier}" + if (owner) " · device owner" else ""
        } else "Not yet registered"
    }

    companion object {
        private const val REQUEST_VPN = 4701
    }
}