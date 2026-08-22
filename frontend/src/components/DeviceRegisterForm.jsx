import { Plus } from "lucide-react";
import { useState } from "react";
import { api } from "../lib/api.js";

const blank = {
  name: "",
  email: "",
  phone: "",
  identifier: "",
  serial: "",
  device_type: "phone",
  consent_source: "manual-admin",
  consent_scope: "live-location,history,alerts",
};

export default function DeviceRegisterForm({ onRegistered, onError }) {
  const [form, setForm] = useState(blank);
  const [error, setError] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  function update(field, value) {
    setForm((current) => ({ ...current, [field]: value }));
  }

  function validateForm() {
    if (!form.name.trim()) return "Name is required";
    if (!form.email.trim()) return "Email is required";
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email)) return "Invalid email format";
    if (!form.phone.trim()) return "Phone is required";
    return null;
  }

  async function submit(event) {
    event.preventDefault();
    setError("");
    
    const validationError = validateForm();
    if (validationError) {
      setError(validationError);
      onError?.(validationError);
      return;
    }

    setIsSubmitting(true);
    try {
      const payload = { ...form };
      if (!payload.identifier) delete payload.identifier;
      if (!payload.serial) delete payload.serial;
      const device = await api.register(payload);
      setForm(blank);
      onRegistered(device);
    } catch (err) {
      const errorMsg = err.message || "Registration failed";
      setError(errorMsg);
      onError?.(errorMsg);
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <section className="panel register-panel">
      <div className="panel-title">
        <span>REGISTER</span>
        <Plus size={15} />
      </div>
      <form onSubmit={submit} className="register-grid">
        <input 
          placeholder="Name" 
          value={form.name} 
          onChange={(event) => update("name", event.target.value)} 
          required 
          disabled={isSubmitting}
        />
        <input 
          placeholder="Email" 
          type="email"
          value={form.email} 
          onChange={(event) => update("email", event.target.value)} 
          required 
          disabled={isSubmitting}
        />
        <input 
          placeholder="Phone" 
          type="tel"
          value={form.phone} 
          onChange={(event) => update("phone", event.target.value)} 
          required 
          disabled={isSubmitting}
        />
        <input 
          placeholder="Identifier / UUID" 
          value={form.identifier} 
          onChange={(event) => update("identifier", event.target.value)}
          disabled={isSubmitting}
        />
        <select value={form.device_type} onChange={(event) => update("device_type", event.target.value)} disabled={isSubmitting}>
          <option value="vehicle">vehicle</option>
          <option value="motorcycle">motorcycle</option>
          <option value="phone">phone</option>
          <option value="laptop">laptop</option>
          <option value="other">other</option>
        </select>
        <button className="command-button" type="submit" disabled={isSubmitting}>
          {isSubmitting ? "REGISTERING..." : "REGISTER"}
        </button>
      </form>
      {error && <div className="inline-error">{error}</div>}
    </section>
  );
}
