const form = document.querySelector("#queryForm");
const button = document.querySelector("#queryButton");
const output = document.querySelector("#output");
const commandLine = document.querySelector("#commandLine");
const returnCode = document.querySelector("#returnCode");
const lastQuery = document.querySelector("#lastQuery");
const duration = document.querySelector("#duration");
const addressList = document.querySelector("#addressList");
const recordList = document.querySelector("#recordList");
const statusBadge = document.querySelector("#statusBadge");
const statusLabel = document.querySelector("#statusLabel");
const statusText = document.querySelector("#statusText");
const serverInput = document.querySelector("#server");
const portInput = document.querySelector("#port");
const domainInput = document.querySelector("#domain");
const typeInput = document.querySelector("#type");

function defaultRelayServer() {
  const host = window.location.hostname;
  if (!host || host === "localhost") {
    return "127.0.0.1";
  }
  return host;
}

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

function renderCommandPreview() {
  const payload = payloadFromForm();
  const server = payload.server || "127.0.0.1";
  const port = payload.port || "1053";
  const domain = payload.domain || "www.baidu.com";
  const qtype = payload.type || "A";
  commandLine.textContent = `dig @${server} -p ${port} ${domain} ${qtype} +time=5 +tries=1`;
}

function renderAnswers(records = []) {
  const addresses = records.filter((record) => record.address);

  if (addresses.length === 0) {
    addressList.innerHTML = "<span class=\"empty-line\">No A/AAAA address returned.</span>";
  } else {
    addressList.innerHTML = addresses
      .map((record) => `<span class="address-chip">${record.address}</span>`)
      .join("");
  }

  if (records.length === 0) {
    recordList.innerHTML = "";
    return;
  }

  recordList.innerHTML = `
    <table>
      <thead>
        <tr>
          <th>Name</th>
          <th>Type</th>
          <th>Value</th>
        </tr>
      </thead>
      <tbody>
        ${records.map((record) => `
          <tr>
            <td>${escapeHtml(record.name)}</td>
            <td>${escapeHtml(record.type)}</td>
            <td>${escapeHtml(record.value)}</td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function renderResult(data) {
  commandLine.textContent = data.command || "-";
  duration.textContent = `${data.duration_ms || 0} ms`;
  returnCode.textContent = String(data.returncode ?? "-");
  lastQuery.textContent = `${domainInput.value.trim()} ${typeInput.value.trim()}`;
  renderAnswers(data.answers || []);

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
  addressList.innerHTML = "<span class=\"empty-line\">Waiting for answer...</span>";
  recordList.innerHTML = "";

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
      stderr: error.message,
      answers: []
    });
    setStatus("error", "FAILED");
  } finally {
    button.disabled = false;
  }
});

serverInput.value = defaultRelayServer();
renderCommandPreview();

[serverInput, portInput, domainInput, typeInput].forEach((control) => {
  control.addEventListener("input", renderCommandPreview);
  control.addEventListener("change", renderCommandPreview);
});
