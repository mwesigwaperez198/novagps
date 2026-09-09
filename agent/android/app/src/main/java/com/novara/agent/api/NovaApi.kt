package com.novara.agent.api

import android.content.Context
import com.novara.agent.util.Config
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import java.io.IOException
import java.util.concurrent.TimeUnit

/**
 * Thin HTTP client over the NOVA backend. Device-facing endpoints
 * authenticate by device identity (identifier / device_id) exactly like
 * POST /update-location, so no operator token is required on-device.
 */
object NovaApi {
    private val json = Json { ignoreUnknownKeys = true }
    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(20, TimeUnit.SECONDS)
        .writeTimeout(20, TimeUnit.SECONDS)
        .build()

    private val JSON = "application/json; charset=utf-8".toMediaType()

    fun sendLocation(context: Context, update: LocationUpdate): LocationResponse {
        val body = json.encodeToString(LocationUpdate.serializer(), update)
            .toRequestBody(JSON)
        val request = Request.Builder()
            .url("${Config.serverUrl}/update-location")
            .post(body)
            .build()
        return execute(request, LocationResponse.serializer())
    }

    fun grantConsent(identifier: String): Boolean {
        val body = json.encodeToString(
            ConsentRequest.serializer(),
            ConsentRequest(identifier = identifier, scope = "location,tracking,security", granted = true),
        ).toRequestBody(JSON)
        val request = Request.Builder()
            .url("${Config.serverUrl}/consent")
            .post(body)
            .build()
        return runCatching {
            client.newCall(request).execute().use { it.isSuccessful }
        }.getOrDefault(false)
    }

    fun pullCommands(context: Context): List<RemoteCommand> {
        val pull = CommandPull(identifier = Config.identifier)
        val request = Request.Builder()
            .url("${Config.serverUrl}/device/pull-commands")
            .post(json.encodeToString(CommandPull.serializer(), pull).toRequestBody(JSON))
            .build()
        val response = execute(request, CommandPullResponse.serializer())
        return response.commands
    }

    fun ackCommand(context: Context, commandId: String) {
        val ack = CommandAck(identifier = Config.identifier, command_id = commandId)
        val request = Request.Builder()
            .url("${Config.serverUrl}/device/ack-command")
            .post(json.encodeToString(CommandAck.serializer(), ack).toRequestBody(JSON))
            .build()
        client.newCall(request).execute().use { /* fire and forget */ }
    }

    private inline fun <reified T> execute(request: Request, serializer: kotlinx.serialization.KSerializer<T>): T {
        var response: Response? = null
        try {
            response = client.newCall(request).execute()
            val text = response.body?.string().orEmpty()
            if (!response.isSuccessful) {
                throw IOException("NOVA ${response.code}: $text")
            }
            return json.decodeFromString(serializer, text)
        } finally {
            response?.close()
        }
    }
}