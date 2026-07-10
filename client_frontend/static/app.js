const form = document.querySelector("#queryForm");
const button = document.querySelector("#queryButton");
const output = document.querySelector("#output");
const commandLine = document.querySelector("#commandLine");
const returnCode = document.querySelector("#returnCode");
const lastQuery = document.querySelector("#lastQuery");
const duration = document.querySelector("#duration");
const statusBadge = document.querySelector("#statusBadge");
const statusLabel = document.querySelector("#statusLabel");
const statusText = document.querySelector("#statusText");
const serverInput = document.querySelector("#server");
const portInput = document.querySelector("#port");
const domainInput = document.querySelector("#domain");
const typeInput = document.querySelector("#type");

function setStatus(kind, text) {
  statusBadge.className = `status ${kind}`;
  statusLabel.textContent = text;
  statusText.textContent = text;
}

function payloadFromForm() {
  return {
    server: serverInput.value.trim(),
    port: portInput.value.trim(),
    domain: domainInput.value.trim(),
    type: typeInput.value.trim()
  };
}

function renderResult(data) {
  commandLine.textContent = data.command || "-";
  duration.textContent = `${data.duration_ms || 0} ms`;
  returnCode.textContent = String(data.returncode ?? "-");
  lastQuery.textContent = `${domainInput.value.trim()} ${typeInput.value.trim()}`;

  const parts = [];
  if (data.stdout) {
    parts.push(data.stdout.trimEnd());
  }
  if (data.stderr) {
    parts.push(data.stderr.trimEnd());
  }
  if (data.error) {
    parts.push(data.error);
  }
  output.textContent = parts.join("\n\n") || "No output.";
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  button.disabled = true;
  setStatus("running", "QUERYING");
  output.textContent = "Querying...";

  try {
    const response = await fetch("/api/query", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payloadFromForm())
    });
    const data = await response.json();
    renderResult(data);
    setStatus(data.ok ? "ok" : "error", data.ok ? "DONE" : "FAILED");
  } catch (error) {
    renderResult({
      ok: false,
      command: "-",
      duration_ms: 0,
      returncode: "-",
      stderr: error.message
    });
    setStatus("error", "FAILED");
  } finally {
    button.disabled = false;
  }
});
