import React, { useState } from "react";
import { createRoot } from "react-dom/client";
import zxcvbn from "zxcvbn";
import "./styles.css";

const labels = ["Very weak", "Weak", "Fair", "Strong", "Very strong"];

async function sha1(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-1", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
}

async function verifier(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`securegate-demo:v1:${value}`));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function checkPassword(password) {
  const hash = await sha1(password);
  const response = await fetch("/api/password/check", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ prefix: hash.slice(0, 5) }) });
  if (!response.ok) throw new Error(response.status === 503 ? "Safety service is temporarily unavailable." : "Could not check password safety.");
  const { suffixes } = await response.json();
  return { score: zxcvbn(password).score, breached: suffixes.some((entry) => entry.suffix === hash.slice(5)) };
}

function App() {
  const [mode, setMode] = useState("signup");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const strength = zxcvbn(password).score;
  const submit = async (event) => {
    event.preventDefault(); setResult(null); setBusy(true);
    try {
      const safety = await checkPassword(password);
      if (safety.breached) { setResult({ kind: "error", text: "Choose a different password. This one appears in known breach data." }); return; }
      if (safety.score < 2) { setResult({ kind: "error", text: "Choose a stronger password before continuing." }); return; }
      const response = await fetch(`/api/accounts/${mode}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email, verifier: await verifier(password) }) });
      if (!response.ok) throw new Error("Account service is unavailable.");
      setResult({ kind: "success", text: mode === "signup" ? "Demo account created securely." : "Reset request accepted securely." });
      setPassword("");
    } catch (error) { setResult({ kind: "error", text: error.message }); }
    finally { setBusy(false); }
  };
  return <main><div className="shell"><header><span className="eyebrow">SECUREGATE / PASSWORD SAFETY</span><h1>Keep compromised passwords out.</h1><p className="lede">A privacy-first demo that checks passwords against breach intelligence without sending your password or full hash anywhere.</p></header>
    <section className="card"><div className="tabs"><button className={mode === "signup" ? "active" : ""} onClick={() => setMode("signup")}>Create account</button><button className={mode === "reset" ? "active" : ""} onClick={() => setMode("reset")}>Reset password</button></div>
      <form onSubmit={submit}><label>Email address<input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com" required /></label><label>New password<input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Use a unique passphrase" minLength="8" required /></label>
      <div className="meter"><div className="meter-head"><span>Password strength</span><strong>{password ? labels[strength] : "Not entered"}</strong></div><div className="bars">{[0,1,2,3,4].map((bar) => <i className={bar <= strength && password ? `fill level-${strength}` : ""} key={bar} />)}</div></div>
      <button className="primary" disabled={busy}>{busy ? "Checking safely…" : mode === "signup" ? "Create protected account" : "Request reset"}</button></form>
      {result && <div className={`result ${result.kind}`} role="status">{result.text}</div>}
    </section><div className="privacy"><span>◇</span><div><strong>Privacy by design</strong><p>Only a 5-character SHA-1 prefix leaves this browser. The suffix comparison happens locally, and the backend stores only an Argon2id hash of a client-derived verifier.</p></div></div>
    <footer><span>SECUREGATE DEMO</span><span>Browser-first · k-anonymous · no raw passwords</span></footer></div></main>;
}
createRoot(document.getElementById("root")).render(<App />);
