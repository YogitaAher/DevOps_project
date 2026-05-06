import { useState } from "react";
const API_BASE =
  import.meta.env.VITE_API_URL || "http://54.158.223.156:30007";
function renderJson(value) {
  return <pre className="json-output">{JSON.stringify(value, null, 2)}</pre>;
}

function SectionCard({ title, children }) {
  return (
    <section className="card">
      <h2>{title}</h2>
      {children}
    </section>
  );
}

export default function App() {
  const [email, setEmail] = useState("");
  const [username, setUsername] = useState("");
  const [loading, setLoading] = useState({ email: false, github: false, health: false });
  const [result, setResult] = useState({ email: null, github: null, health: null });
  const [error, setError] = useState({ email: null, github: null, health: null });

  const requestJson = async (path, method = "POST", body = null) => {
    const url = `${API_BASE}${path}`;
    const init = {
      method,
      headers: { "Content-Type": "application/json" },
    };

    if (body) {
      init.body = JSON.stringify(body);
    }

    const response = await fetch(url, init);
    if (!response.ok) {
      const text = await response.text();
      throw new Error(`${response.status} ${response.statusText}: ${text}`);
    }
    return response.json();
  };

  const handleEmail = async () => {
    setLoading((prev) => ({ ...prev, email: true }));
    setError((prev) => ({ ...prev, email: null }));
    try {
      const data = await requestJson("/scan/email", "POST", { email });
      setResult((prev) => ({ ...prev, email: data }));
    } catch (err) {
      setError((prev) => ({ ...prev, email: err.message }));
      setResult((prev) => ({ ...prev, email: null }));
    } finally {
      setLoading((prev) => ({ ...prev, email: false }));
    }
  };

  const handleGithub = async () => {
    setLoading((prev) => ({ ...prev, github: true }));
    setError((prev) => ({ ...prev, github: null }));
    try {
      const data = await requestJson("/scan/github", "POST", { username });
      setResult((prev) => ({ ...prev, github: data }));
    } catch (err) {
      setError((prev) => ({ ...prev, github: err.message }));
      setResult((prev) => ({ ...prev, github: null }));
    } finally {
      setLoading((prev) => ({ ...prev, github: false }));
    }
  };

  const handleHealth = async () => {
    setLoading((prev) => ({ ...prev, health: true }));
    setError((prev) => ({ ...prev, health: null }));
    try {
      const data = await requestJson("/health", "GET");
      setResult((prev) => ({ ...prev, health: data }));
    } catch (err) {
      setError((prev) => ({ ...prev, health: err.message }));
      setResult((prev) => ({ ...prev, health: null }));
    } finally {
      setLoading((prev) => ({ ...prev, health: false }));
    }
  };

  return (
    <div className="app-shell">
      <header className="hero">
        <div>
          <p className="eyebrow">Kubernetes Data Leak Dashboard</p>
          <h1>API Gateway Scanner Console</h1>
          <p>Use the API Gateway endpoints only. Do not call backend services directly.</p>
        </div>
        <div className="badge">API: {API_BASE}</div>
      </header>

      <main className="grid">
        <SectionCard title="Email Breach Scanner">
          <label>
            Email address
            <input
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="user@example.com"
            />
          </label>
          <button onClick={handleEmail} disabled={!email || loading.email}>
            {loading.email ? "Scanning..." : "Scan Email"}
          </button>
          {error.email && <div className="error">{error.email}</div>}
          {result.email && (
            <div className="response-box">
              <div className="response-meta">Breaches found: {result.email.breaches?.length ?? 0}</div>
              {renderJson(result.email)}
            </div>
          )}
        </SectionCard>

        <SectionCard title="GitHub Scanner">
          <label>
            GitHub username
            <input
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="githubuser"
            />
          </label>
          <button onClick={handleGithub} disabled={!username || loading.github}>
            {loading.github ? "Scanning..." : "Scan GitHub"}
          </button>
          {error.github && <div className="error">{error.github}</div>}
          {result.github && (
            <div className="response-box">
              <div className="response-meta">Leaks found: {result.github.leaks?.length ?? 0}</div>
              {renderJson(result.github)}
            </div>
          )}
        </SectionCard>

        <SectionCard title="System Health Check">
          <button onClick={handleHealth} disabled={loading.health}>
            {loading.health ? "Checking..." : "Check Health"}
          </button>
          {error.health && <div className="error">{error.health}</div>}
          {result.health && (
            <div className="response-box">{renderJson(result.health)}</div>
          )}
        </SectionCard>
      </main>
    </div>
  );
}
