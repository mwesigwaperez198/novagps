package com.novara.agent.api

import kotlinx.serialization.Serializable

// Mirror of backend/schemas.py — keep field names identical to the wire
// contract so the FastAPI models accept these payloads untouched.

@Serializable
data class RegisterRequest(
    val name: String = "Agent device",
    val email: String = "",
    val phone: String = "",
    val identifier: String,
    val serial: String = "",
    val imei: String = "",
    val model: String = "",
    val manufacturer: String = "",
    val os_type: String = "android",
    val os_version: String = "",
    val device_type: String = "phone",
    val consent_source: String = "agent",
    val consent_scope: String = "location,tracking,security",
)

@Serializable
data class ConsentRequest(
    val device_id: String? = null,
    val identifier: String? = null,
    val scope: String = "location,tracking,security",
    val granted: Boolean = true,
)

@Serializable
data class LocationUpdate(
    val device_id: String? = null,
    val identifier: String? = null,
    val latitude: Double,
    val longitude: Double,
    val altitude: Double? = null,
    val speed: Double? = null,
    val heading: Double? = null,
    val accuracy: Double? = null,
    val source: String = "mobile",
    val raw_payload: Map<String, Any> = emptyMap(),
)

@Serializable
data class CommandPull(
    val device_id: String? = null,
    val identifier: String? = null,
)

@Serializable
data class CommandAck(
    val device_id: String? = null,
    val identifier: String? = null,
    val command_id: String,
)

@Serializable
data class RemoteCommand(
    val command_id: String,
    val command_type: String,
    val payload: Map<String, Any> = emptyMap(),
    val status: String = "pending",
    val attempts: Int = 0,
    val created_at: String = "",
)

@Serializable
data class CommandPullResponse(
    val commands: List<RemoteCommand> = emptyList(),
)

@Serializable
data class LocationResponse(
    val status: String = "",
    val location_id: String? = null,
    val place_name: String? = null,
)