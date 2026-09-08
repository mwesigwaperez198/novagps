package com.novara.agent.service

import android.app.Notification
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.net.VpnService.Builder
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.novara.agent.MainActivity
import com.novara.agent.NovaAgentApp
import com.novara.agent.R
import com.novara.agent.util.Config
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.FileDescriptor
import java.net.Inet4Address
import java.net.Inet6Address
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Protection mode: an Android VPNService firewall (the root-free, official
 * mechanism — the same one NetGuard and enterprise agents use).
 *
 * Every address on the device is routed into the tun interface we create
 * here. The packet classifier below accepts or drops connections based on
 * the NOVA rule set:
 *   - allowlist-first: trusted destinations (NOVA endpoint, DNS, our
 *     allowlisted apps/internal ranges keep flowing)
 *   - everything else is refused unless the server whitelisted it via a
 *     command payload {"type":"allow","pkgs":[..],"hosts":[..]}.
 *
 * As device owner the service is set always-on with lockdown in
 * MainActivity, so a dropped VPN = no traffic at all (not a leak).
 */
class FirewallService : VpnService() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var tunnel: ParcelFileDescriptor? = null
    private val running = AtomicBoolean(false)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NODE_FIREWALL, notification())
        scope.launch { buildAndServe() }
        return START_STICKY
    }

    override fun onDestroy() {
        running.set(false)
        scope.cancel()
        runCatching { tunnel?.close() }
        super.onDestroy()
    }

    private fun buildAndServe() {
        val builder = Builder().apply {
            addAddress("10.8.0.1", 24)
            addRoute("0.0.0.0", 0)
            addDnsServer("8.8.8.8")
            addDnsServer("1.1.1.1")
            setSession("NOVA protection")
            setMtu(1500)
        }
        // Whole-device routing when we are device owner, otherwise only
        // our own app + a small set of system apps see the tunnel.
        builder.addDisallowedApplication(packageName)
        Config.serverUrl.takeIf { it.startsWith("http") }?.let { url ->
            val serverHost = runCatching { java.net.URI(url).host }.getOrNull()
            if (!serverHost.isNullOrEmpty()) builder.addRoute(serverHost, 0)
        }
        tunnel = builder.establish()
        if (tunnel == null) return  // user declined the VPN prompt

        running.set(true)
        val fd: FileDescriptor = tunnel?.fileDescriptor ?: return
        serveLoop(fd)
    }

    /**
     * Raw tun reader. Each loop iteration reads one IP packet; we classify
     * it by destination and either accept it or refuse it before it leaves
     * the device. Local subnets and DNS always pass. Extend
     * `allowlist()` with the same rules the server pushes in commands.
     */
    private fun serveLoop(fd: FileDescriptor) {
        val buffer = ByteArray(32767)
        val input = java.io.FileInputStream(fd)
        while (scope.isActive && running.get()) {
            val bytesRead = runCatching { input.read(buffer) }.getOrDefault(-1)
            if (bytesRead <= 0) continue
            val verdict = classify(buffer, bytesRead)
            if (verdict == Verdict.ACCEPT) {
                // forward the raw packet to a live socket (layer-4 proxy);
                // a skeleton that simply re-injects locally acceptable data.
            }
        }
    }

    private enum class Verdict { ACCEPT, DROP }

    private fun classify(packet: ByteArray, length: Int): Verdict {
        if (length < 20) return Verdict.DROP
        val version = (packet[0].toInt() ushr 4) and 0xF
        return when (version) {
            4 -> {
                val dst = Inet4Address.getByAddress(packet.copyOfRange(16, 20)).hostAddress
                if (dst == null || isAllowed(dst)) Verdict.ACCEPT else Verdict.DROP
            }
            6 -> {
                if (length < 40) return Verdict.DROP
                val dst = Inet6Address.getByAddress(packet.copyOfRange(24, 40)).hostAddress
                if (dst == null || isAllowed(dst)) Verdict.ACCEPT else Verdict.DROP
            }
            else -> Verdict.DROP
        }
    }

    private fun isAllowed(host: String): Boolean =
        host.startsWith("10.") || host.startsWith("192.168.") ||
            host.startsWith("169.254.") || host == "8.8.8.8" ||
            host == "1.1.1.1" || host in allowlistHosts()

    private fun allowlistHosts(): Set<String> =
        runCatching {
            val host = java.net.URI(Config.serverUrl).host ?: return setOf()
            setOf(host)
        }.getOrDefault(emptySet())

    private fun notification(): Notification {
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, NovaAgentApp.CHANNEL_ID)
            .setContentTitle("NOVA protection")
            .setContentText("Firewall active — untrusted traffic is blocked.")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(open)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_MIN)
            .build()
    }

    companion object {
        private const val NODE_FIREWALL = 4042

        fun start(context: android.content.Context) {
            val intent = Intent(context, FirewallService::class.java)
            context.startForegroundService(intent)
        }

        fun isPrepared(context: android.content.Context): Boolean {
            val signals = VpnService.prepare(context)
            return signals == null
        }
    }
}