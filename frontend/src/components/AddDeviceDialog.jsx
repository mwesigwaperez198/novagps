import { Check, Copy, X } from "lucide-react";
import { useEffect, useState } from "react";
import { api } from "../lib/api.js";

const blank = {
  name: "",
  email: "",
  phone: "",
  device_type: "phone",
  imei: "",
  model: "",
  manufacturer: "",
  identifier: "",
};

export default function AddDeviceDialog({ open, onClose, onRegistered, onError, defaultEmail = "" }) {
  const [form, setForm] = useState(blank);
  const [error, setError] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [paired, setPaired] = useState(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (open) {
      setForm((current) => ({ ...blank, email: current.email || defaultEmail }));
      setError("");
      setPaired(null);
    }
  }, [open, defaultEmail]);

  if (!open) return null;

  function update(field, value) {
    setForm((current) => ({ ...current, [field]: value }));
  }

  async function submit(event) {
    event.preventDefault();
    setError("");
    if (!form.name.trim()) return setError("Give the device a name.");
    if (!form.email.trim()) return setError("An email is required for the device record.");
    if (!form.phone.trim()) return setError("A phone number is required.");

    setIsSubmitting(true);
    try {
      const payload = { ...form, consent_source: "dashboard", consent_scope: "live-location,history,alerts" };
      for (const key of ["imei", "model", "manufacturer", "identifier"]) {
        if (!payload[key]) delete payload[key];
      }
      const device = await api.register(payload);
      setPaired(device);
      onRegistered?.(device);
    } catch (err) {
      setError(err.message || "Registration failed");
      onError?.(err.message || "Registration failed");
    } finally {
      setIsSubmitting(false);
    }
  }

  function copyIdentifier() {
    if (!paired) return;
    const id = paired.identifier || paired.id;
    navigator.clipboard?.writeText(id).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-panel glass-card add-device-modal" onClick={(event) => event.stopPropagation()}>
        <div className="modal-header">
          <span>{paired ? "DEVICE ADDED" : "ADD A DEVICE"}</span>
          <button className="icon-button" onClick={onClose} type="button" title="Close">
            <X size={16} />
          </button>
        </div>

        {paired ? (
          <div className="pairing-guide">
            <p className="pairing-ok">✓ {paired.name} is registered and ready to track.</p>
            <p className="pairing-step">
              <strong>1.</strong> Install the NOVA agent (or any Traccar-compatible client) on the device.
            </p>
            <p className="pairing-step">
              <strong>2.</strong> Set its server to <code>{typeof location !== "undefined" ? location.origin : "https://novagps.onrender.com"}</code> and its
              identifier to the value below.
            </p>
            <div className="pairing-id">
              <code>{paired.identifier || paired.id}</code>
              <button className="command-button" onClick={copyIdentifier} type="button">
                {copied ? <Check size={14} /> : <Copy size={14} />} {copied ? "COPIED" : "COPY"}
              </button>
            </div>
            <p className="pairing-note">
              The device appears on the map the moment its first location ping arrives — no
              further setup here.
            </p>
            <button className="command-button" onClick={onClose} type="button">DONE</button>
          </div>
        ) : (
          <form onSubmit={submit} className="register-grid">
            <input placeholder="Device name (e.g. Mum's phone)" value={form.name}
              onChange={(e) => update("name", e.target.value)} disabled={isSubmitting} required />
            <input placeholder="Owner phone" type="tel" value={form.phone}
              onChange={(e) => update("phone", e.target.value)} disabled={isSubmitting} required />
            <input placeholder="Owner email" type="email" value={form.email}
              onChange={(e) => update("email", e.target.value)} disabled={isSubmitting} required />
            <select value={form.device_type} onChange={(e) => update("device_type", e.target.value)} disabled={isSubmitting}>
              <option value="phone">phone</option>
              <option value="vehicle">vehicle</option>
              <option value="motorcycle">motorcycle</option>
              <option value="laptop">laptop</option>
              <option value="other">other</option>
            </select>
            <input placeholder="IMEI (optional)" value={form.imei}
              onChange={(e) => update("imei", e.target.value)} disabled={isSubmitting} />
            <input placeholder="Model (optional)" value={form.model}
              onChange={(e) => update("model", e.target.value)} disabled={isSubmitting} />
            <input placeholder="Manufacturer (optional)" value={form.manufacturer}
              onChange={(e) => update("manufacturer", e.target.value)} disabled={isSubmitting} />
            <input placeholder="Identifier / UUID (optional)" value={form.identifier}
              onChange={(e) => update("identifier", e.target.value)} disabled={isSubmitting} />
            <button className="command-button" type="submit" disabled={isSubmitting}>
              {isSubmitting ? "ADDING..." : "ADD DEVICE"}
            </button>
          </form>
        )}

        {error && <div className="inline-error">{error}</div>}
      </div>
    </div>
  );
}
