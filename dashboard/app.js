const state = {
  currentLog: "fwd-replicate",
  status: null,
};

const metricKeys = [
  ["rx", "received"],
  ["replicated", "replicated"],
  ["passed", "passed"],
  ["duplicates", "duplicates dropped"],
  ["malformed", "malformed"],
  ["no_config", "no config"],
];

const logLabels = {
  "fwd-replicate": "Forward replicate",
  "fwd-eliminate": "Forward eliminate",
  "rev-replicate": "Return replicate",
  "rev-eliminate": "Return eliminate",
};

function el(id) {
  return document.getElementById(id);
}

function setBadge(node, text, tone) {
  node.textContent = text;
  node.classList.toggle("ok", tone === "ok");
  node.classList.toggle("bad", tone === "bad");
  node.classList.toggle("warn", tone === "warn");
}

async function fetchStatus() {
  const res = await fetch("/api/status", { cache: "no-store" });
  state.status = await res.json();
  render();
}

async function runAction(action) {
  setButtonsDisabled(true);
  try {
    const res = await fetch("/api/action", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ action }),
    });
    if (!res.ok) {
      await res.json().catch(() => ({}));
    }
  } finally {
    setTimeout(() => {
      setButtonsDisabled(false);
      fetchStatus();
    }, 650);
  }
}

function setButtonsDisabled(disabled) {
  document.querySelectorAll("[data-action]").forEach((button) => {
    button.disabled = disabled;
  });
}

function byName(status, name) {
  return (status.links || []).find((item) => item.name === name);
}

function isUp(item) {
  return Boolean(item?.exists) && String(item.state).toLowerCase() === "up";
}

function isDown(item) {
  return Boolean(item?.exists) && String(item.state).toLowerCase() === "down";
}

function stateText(item) {
  if (!item?.exists) return "not created";
  return String(item.state).toLowerCase();
}

function pathTone(item) {
  if (!item?.exists) return "pending";
  if (isDown(item)) return "down";
  return "";
}

function renderMetrics(target, stats) {
  const data = stats || {};
  target.innerHTML = metricKeys
    .map(([key, label]) => {
      const value = data[key] ?? 0;
      return `<div class="metric"><span>${label}</span><strong>${value}</strong></div>`;
    })
    .join("");
}

function combineDirection(status, replicateName, eliminateName) {
  const replicate = status.logs?.[replicateName]?.stats || {};
  const eliminate = status.logs?.[eliminateName]?.stats || {};
  return {
    rx: replicate.rx ?? 0,
    replicated: replicate.replicated ?? 0,
    passed: eliminate.passed ?? 0,
    duplicates: eliminate.duplicates ?? 0,
    malformed: (replicate.malformed ?? 0) + (eliminate.malformed ?? 0),
    no_config: (replicate.no_config ?? 0) + (eliminate.no_config ?? 0),
  };
}

function renderPaths(status) {
  const ab0 = byName(status, "ab0");
  const ab1 = byName(status, "ab1");
  const pathA = el("pathAb0");
  const pathB = el("pathAb1");

  pathA.classList.toggle("pending", !ab0?.exists);
  pathA.classList.toggle("down", pathTone(ab0) === "down");
  pathA.querySelector("strong").textContent = ab0?.exists ? (isDown(ab0) ? "failed" : "active") : "not created";

  pathB.classList.toggle("pending", !ab1?.exists);
  pathB.classList.toggle("down", pathTone(ab1) === "down");
  pathB.querySelector("strong").textContent = ab1?.exists ? (isDown(ab1) ? "failed" : "active") : "not created";
}

function renderState(status) {
  const ab0 = byName(status, "ab0");
  const ab1 = byName(status, "ab1");
  const topologyReady = Boolean(status.topologyReady);
  const frerRunning = Boolean(status.frerRunning);
  const trafficSeen = Boolean(status.trafficSeen);

  el("networkState").textContent = topologyReady ? "ready" : "not created";
  el("programState").textContent = frerRunning ? "running" : "stopped";
  el("pathAState").textContent = stateText(ab0);
  el("pathBState").textContent = stateText(ab1);

  let title = "Start the demo";
  let message = "Click Start complete demo. It will build, create the network, and attach FRER in order.";

  if (!status.isRoot) {
    title = "Restart with sudo";
    message = "Network namespaces and XDP attach need root privileges. Stop this server and run sudo make dashboard.";
  } else if (!status.buildOk) {
    title = "Build required";
    message = "Compile the eBPF object and userspace loader before attaching FRER.";
  } else if (!topologyReady) {
    title = "Network not created";
    message = "Create network first. Without the virtual interfaces, Attach FRER will fail with unknown interface errors.";
  } else if (!frerRunning) {
    title = "FRER not attached";
    message = status.frerHealth?.message || "The network exists. Attach FRER to load the XDP replication and elimination programs.";
  } else if (!trafficSeen) {
    title = "Ready for traffic";
    message = "FRER is running. Click Run test traffic to make the counters move.";
  } else if (isDown(ab0) && !isDown(ab1)) {
    title = "Path A failed, service protected";
    message = "Path B is still active, so protected traffic should continue.";
  } else if (isDown(ab0) && isDown(ab1)) {
    title = "Both paths failed";
    message = "Both redundant links are down, so traffic should stop until a path is recovered.";
  } else {
    title = "Demo running";
    message = "Traffic is flowing through the protected stream. Fail Path A to demonstrate recovery.";
  }

  el("stateTitle").textContent = title;
  el("stateMessage").textContent = message;
}

function renderTabs(status) {
  const names = Object.keys(logLabels);
  el("logTabs").innerHTML = names
    .map((name) => `<button class="${name === state.currentLog ? "active" : ""}" data-log="${name}">${logLabels[name]}</button>`)
    .join("");

  document.querySelectorAll("[data-log]").forEach((button) => {
    button.addEventListener("click", () => {
      state.currentLog = button.dataset.log;
      render();
    });
  });

  const log = status.logs?.[state.currentLog]?.lines || [];
  el("frerLog").textContent = log.length ? log.join("\n") : "Attach FRER to see program output.";
}

function renderButtons(status) {
  const running = new Set(status.runningActions || []);
  const busy = running.size > 0;
  const topologyReady = Boolean(status.topologyReady);
  const frerRunning = Boolean(status.frerRunning);

  document.querySelectorAll("[data-action]").forEach((button) => {
    const action = button.dataset.action;
    let blocked = false;

    if (!status.isRoot && action !== "build") blocked = true;
    if (["start_frer", "ping", "fail_ab0", "recover_ab0", "fail_both", "recover_both"].includes(action) && !topologyReady) blocked = true;
    if (["ping", "fail_ab0", "recover_ab0", "fail_both", "recover_both"].includes(action) && !frerRunning) blocked = true;

    button.disabled = busy || blocked;
    button.classList.toggle("blocked", blocked && !busy);
  });
}

function render() {
  const status = state.status;
  if (!status) return;

  setBadge(el("rootBadge"), status.isRoot ? "sudo ready" : "needs sudo", status.isRoot ? "ok" : "bad");
  setBadge(el("buildBadge"), status.buildOk ? "built" : "not built", status.buildOk ? "ok" : "warn");
  setBadge(el("topologyBadge"), status.topologyReady ? "network ready" : "network not created", status.topologyReady ? "ok" : "warn");
  setBadge(el("frerBadge"), status.frerRunning ? "FRER running" : "FRER stopped", status.frerRunning ? "ok" : "warn");
  setBadge(el("trafficBadge"), status.trafficSeen ? "traffic seen" : "no traffic yet", status.trafficSeen ? "ok" : "warn");

  const forwardStats = combineDirection(status, "fwd-replicate", "fwd-eliminate");
  const reverseStats = combineDirection(status, "rev-replicate", "rev-eliminate");
  renderMetrics(el("forwardMetrics"), forwardStats);
  renderMetrics(el("reverseMetrics"), reverseStats);
  renderPaths(status);
  renderState(status);
  renderTabs(status);
  renderButtons(status);

  el("forwardHint").textContent = status.trafficSeen
    ? "Received, passed, and duplicate counters come directly from BPF map stats printed by the loader."
    : "Counters stay at 0 until FRER is attached and Run test traffic is clicked.";
  el("reverseHint").textContent = status.trafficSeen
    ? "Return traffic confirms ping replies are protected in the reverse direction."
    : "This stays quiet until ping replies are flowing back from PC2.";

  const actionLines = status.actionLog || [];
  el("actionLog").textContent = actionLines.length ? actionLines.join("\n") : "Waiting for actions...";
}

document.querySelectorAll("[data-action]").forEach((button) => {
  button.addEventListener("click", () => runAction(button.dataset.action));
});

el("refreshBtn").addEventListener("click", fetchStatus);

fetchStatus();
setInterval(fetchStatus, 1200);
