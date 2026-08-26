import { useState } from "react";
import { Lock, User } from "lucide-react";
import { api, setAuthToken } from "../lib/api.js";

export default function LoginScreen({ onLogin }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    if (!email.trim() || !password.trim()) {
      setError("Email and password are required");
      return;
    }
    setLoading(true);
    try {
      const result = await api.login({ email, password });
      setAuthToken(result.access_token);
      onLogin(result);
    } catch (err) {
      setError(err.message || "Login failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="login-screen">
      <div className="login-card glass-card">
        <div className="login-brand">
          <div className="brand-mark">N</div>
          <h1>NOVA GPS</h1>
          <p>Consent-first tracking platform</p>
        </div>
        <form onSubmit={handleSubmit} className="login-form">
          <div className="input-group">
            <User size={16} />
            <input
              type="email"
              placeholder="Email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              autoFocus
            />
          </div>
          <div className="input-group">
            <Lock size={16} />
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>
          {error && <div className="login-error">{error}</div>}
          <button className="login-button" type="submit" disabled={loading}>
            {loading ? "AUTHENTICATING..." : "SIGN IN"}
          </button>
        </form>
        <div className="login-footer">
          <span>NOVARA SYSTEMS</span>
        </div>
      </div>
    </div>
  );
}
