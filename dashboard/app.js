const state = {
  currentLog: "fwd-replicate",
  status: null,
};

const metricKeys = ["rx", "replicated", "passed", "duplicates", "malformed", "no_config"];
const logNames = ["fwd-replicate", "fwd-eliminate", "rev-replicate", "rev-eliminate"];

function el(id) {
  return document.getElementById(id);
}

function setBadge(node, text, good) {
  node.textContent = text;
  node.classList.toggle("ok", good === true);
  node.classList.toggle("bad", good === false);
}

async function fetchStatus() {
  const res = await fetch("/api/status", { cache: "no-store" });
  state.status = await res.json();
  render();
}

async function runAction(action) {
  setButtonsDisabled(true);
  try {
    await fetch("/api/action", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ action }),
    });
  } finally {
    setTimeout(() => {
      setButtonsDisabled(false);
      fetchStatus();
    }, 700);
  }
}

function setButtonsDisabled(disabled) {
  document.querySelectorAll("[data-action]").forEach((button) => {
    button.disabled = disabled;
  });
}

function renderMetrics(target, stats) {
  const data = stats || {};
  target.innerHTML = metricKeys
    .map((key) => {
      const label = key.replace("_", " ");
      const value = data[key] ?? 0;
      return `<div class="metric"><span>${label}</span><strong>${value}</strong></div>`;
    })
    .join("");
}

function renderLinks(status) {
  const links = status.links || [];
  el("links").innerHTML = links
    .map((item) => {
      const normalized = item.exists ? item.state.toLowerCase() : "missing";
      return `<div class="link-row"><strong>${item.name}</strong><span class="state ${normalized}">${normalized}</span></div>`;
    })
    .join("");

  const ab0 = links.find((item) => item.name === "ab0");
  const ab1 = links.find((item) => item.name === "ab1");
  el("pathAb0").classList.toggle("down", !ab0 || ab0.state.toLowerCase() === "down" || !ab0.exists);
  el("pathAb1").classList.toggle("down", !ab1 || ab1.state.toLowerCase() === "down" || !ab1.exists);
}

function renderTabs(status) {
  el("logTabs").innerHTML = logNames
    .map((name) => `<button class="${name === state.currentLog ? "active" : ""}" data-log="${name}">${name}</button>`)
    .join("");
  document.querySelectorAll("[data-log]").forEach((button) => {
    button.addEventListener("click", () => {
      state.currentLog = button.dataset.log;
      render();
    });
  });

  const log = status.logs?.[state.currentLog]?.lines || [];
  el("frerLog").textContent = log.length ? log.join("\n") : "No log lines yet.";
}

function render() {
  const status = state.status;
  if (!status) return;

  setBadge(el("rootBadge"), status.isRoot ? "root privileges ready" : "start with sudo", status.isRoot);
  setBadge(el("buildBadge"), status.buildOk ? "build available" : "not built", status.buildOk);
  setBadge(el("frerBadge"), status.frerRunning ? "FRER running" : "FRER stopped", status.frerRunning);

  const forwardStats = status.logs?.["fwd-eliminate"]?.stats || status.logs?.["fwd-replicate"]?.stats;
  const reverseStats = status.logs?.["rev-eliminate"]?.stats || status.logs?.["rev-replicate"]?.stats;
  renderMetrics(el("forwardMetrics"), forwardStats);
  renderMetrics(el("reverseMetrics"), reverseStats);
  renderLinks(status);
  renderTabs(status);

  const actionLines = status.actionLog || [];
  el("actionLog").textContent = actionLines.length ? actionLines.join("\n") : "Waiting for actions...";

  const running = new Set(status.runningActions || []);
  document.querySelectorAll("[data-action]").forEach((button) => {
    button.disabled = running.size > 0;
  });
}

document.querySelectorAll("[data-action]").forEach((button) => {
  button.addEventListener("click", () => runAction(button.dataset.action));
});

el("refreshBtn").addEventListener("click", fetchStatus);

fetchStatus();
setInterval(fetchStatus, 1500);
