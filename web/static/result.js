// Renders a PhishShield analysis result (same shape for every channel).
const COLORS = { safe: "var(--safe)", suspicious: "var(--warn)", phishing: "var(--danger)", unknown: "var(--muted)" };
const LABELS = { safe: "Looks safe", suspicious: "Suspicious", phishing: "Phishing detected", unknown: "No result" };

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function renderResult(el, r) {
  const score = r.risk_score ?? 0;
  const flags = (r.red_flags || []).map(f =>
    `<li class="${f.severity}"><b>${esc(f.title)}</b><span>${esc(f.detail)}</span></li>`).join("");
  const maxC = Math.max(0.001, ...(r.explanation || []).map(e => Math.abs(e.contribution)));
  const bars = (r.explanation || []).map(e => `
    <div class="bar-row" title="${esc(e.direction)}: ${e.contribution}">
      <div class="name">${esc(e.feature)}</div>
      <div class="bar-track"><div class="bar-fill ${e.direction}" style="width:${Math.abs(e.contribution) / maxC * 100}%"></div></div>
      <div class="small muted">${e.contribution > 0 ? "+" : ""}${e.contribution.toFixed(2)}</div>
    </div>`).join("");
  const d = r.details || {};
  const kv = Object.entries(d).filter(([k, v]) => !["links", "all_codes"].includes(k) && v !== "" && v !== null &&
    !(Array.isArray(v) && !v.length)).map(([k, v]) =>
    `<dt>${esc(k.replace(/_/g, " "))}</dt><dd>${esc(Array.isArray(v) ? v.join(", ") : v)}</dd>`).join("");
  const links = (d.links || []).map(l =>
    `<tr><td class="mono">${esc(l.url)}</td><td><span class="badge ${l.verdict}">${l.verdict}</span></td><td class="num">${l.risk_score}</td></tr>`).join("");

  el.innerHTML = `
    <div class="card">
      <div class="verdict">
        <div class="gauge" style="--pct:${score};--col:${COLORS[r.verdict]}"><span>${r.risk_score ?? "–"}</span><small>risk / 100</small></div>
        <div>
          <span class="badge ${r.verdict}">${LABELS[r.verdict]}</span>
          <h2 style="margin-top:10px">${r.verdict === "phishing" ? "Do not trust this " : r.verdict === "suspicious" ? "Be careful with this " : r.verdict === "safe" ? "No major threats in this " : "Couldn't analyse this "}${esc(r.channel === "qr" ? "QR code" : r.channel.toUpperCase() === "SMS" ? "message" : r.channel)}</h2>
          ${r.ml_probability !== null && r.ml_probability !== undefined ? `<div class="muted small">ML model phishing probability: <b>${(r.ml_probability * 100).toFixed(1)}%</b> · ${r.red_flags.length} red flag(s)</div>` : ""}
          ${d.error ? `<div class="error">${esc(d.error)}</div>` : ""}
        </div>
      </div>
    </div>
    <div class="grid grid-2" style="margin-top:18px">
      <div class="card"><h3>🚩 Red flags</h3>${flags ? `<ul class="flags">${flags}</ul>` : `<p class="muted">No rule-based red flags triggered.</p>`}</div>
      <div class="card"><h3>🧠 Why the AI decided this</h3>
        ${bars ? `<p class="muted small">Words/patterns that pushed the model towards <span style="color:var(--danger)">phishing</span> or <span style="color:var(--safe)">legitimate</span>.</p><div class="bars">${bars}</div>` : `<p class="muted">No model explanation for this content type.</p>`}
      </div>
    </div>
    ${links ? `<div class="card" style="margin-top:18px"><h3>🔗 Links found inside</h3><table><tr><th>URL</th><th>Verdict</th><th class="num">Risk</th></tr>${links}</table></div>` : ""}
    <div class="grid grid-2" style="margin-top:18px">
      ${kv ? `<div class="card"><h3>📋 Details</h3><dl class="kv">${kv}</dl></div>` : ""}
      <div class="card"><h3>✅ What you should do</h3><ul class="advice">${(r.advice || []).map(a => `<li>${esc(a)}</li>`).join("")}</ul></div>
    </div>`;
  el.classList.add("show");
  el.scrollIntoView({ behavior: "smooth", block: "start" });
}

async function postScan(channel, body, isForm) {
  const res = await fetch(`/api/v1/scan/${channel}`, isForm
    ? { method: "POST", body }
    : { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || "Request failed");
  return data;
}
