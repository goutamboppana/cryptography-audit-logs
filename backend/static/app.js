"use strict";

const $ = (selector, root = document) => root.querySelector(selector);
const studentsBody = $("#students-body");
const auditBody = $("#audit-body");
const notice = $("#notice");
let students = [];
let auditEntries = [];
let auditTotal = 0;
let auditOffset = 0;
const auditLimit = 100;
let verificationCurrent = false;

function showNotice(message, isError = false) {
  notice.textContent = message;
  notice.classList.toggle("error", isError);
  notice.hidden = false;
  window.clearTimeout(showNotice.timer);
  showNotice.timer = window.setTimeout(() => { notice.hidden = true; }, 6500);
}

function markVerificationStale() {
  verificationCurrent = false;
  $("#download-report-button").disabled = true;
  const state = $("#integrity-state");
  state.className = "status-value pending";
  state.replaceChildren(document.createTextNode("Not checked"));
  $("#verified-at").textContent = "Not verified";
  $("#verification-panel").hidden = true;
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = payload.detail;
    const message = Array.isArray(detail) ? detail.map((item) => item.msg).join("; ") : detail;
    throw new Error(message || `Request failed (${response.status})`);
  }
  return payload;
}

function cell(row, value, className = "") {
  const element = document.createElement("td");
  element.className = className;
  element.textContent = value;
  row.append(element);
  return element;
}

function renderStudents() {
  studentsBody.replaceChildren();
  $("#student-count").textContent = `${students.length} ${students.length === 1 ? "record" : "records"}`;
  $("#records-empty").hidden = students.length > 0;
  $(".students-table").hidden = students.length === 0;
  if (!students.length) return;

  for (const student of students) {
    const row = document.createElement("tr");
    const nameCell = cell(row, student.name, "student-name");
    nameCell.title = `Record #${student.id}`;
    cell(row, student.student_number, "student-id");
    cell(row, `${student.marks} / 100`, "student-mark");
    const update = cell(row, "", "");
    const controls = document.createElement("div");
    controls.className = "update-cell";
    const input = document.createElement("input");
    input.type = "number";
    input.min = "0";
    input.max = "100";
    input.required = true;
    input.value = String(student.marks);
    input.setAttribute("aria-label", `New marks for ${student.name}`);
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = "Save";
    button.addEventListener("click", async () => {
      if (!input.reportValidity()) return;
      button.disabled = true;
      try {
        await api(`/api/students/${student.id}/marks`, {
          method: "PATCH", body: JSON.stringify({ marks: Number(input.value) }),
        });
        markVerificationStale();
        showNotice(`Marks updated for ${student.name}; an audit event was recorded.`);
        await refresh();
        await verify();
      } catch (error) { showNotice(error.message, true); }
      finally { button.disabled = false; }
    });
    controls.append(input, button);
    update.append(controls);
    studentsBody.append(row);
  }
}

function formatTime(value) {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : date.toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
}

function actionLabel(action) {
  return ({ student_created: "Student created", marks_updated: "Marks updated" })[action] || action || "Unknown action";
}

function inspectEvent(entry) {
  const fields = {
    "#detail-event-id": entry.event_id,
    "#detail-sequence": String(entry.sequence),
    "#detail-timestamp": `${formatTime(entry.timestamp)} (${entry.timestamp})`,
    "#detail-actor": entry.actor,
    "#detail-action": actionLabel(entry.action),
    "#detail-record-id": String(entry.record_id),
    "#detail-before": entry.before === null ? "—" : JSON.stringify(entry.before, null, 2),
    "#detail-after": JSON.stringify(entry.after, null, 2),
    "#detail-previous-hash": entry.previous_hash,
    "#detail-entry-hash": entry.entry_hash,
    "#detail-hmac": entry.hmac,
  };
  for (const [selector, value] of Object.entries(fields)) $(selector).textContent = value ?? "—";
  const dialog = $("#event-dialog");
  if (typeof dialog.showModal === "function") dialog.showModal();
  else dialog.setAttribute("open", "");
}

function renderAudit() {
  auditBody.replaceChildren();
  $("#entry-count").textContent = String(auditTotal);
  $("#audit-empty").hidden = auditEntries.length > 0;
  $(".audit-panel table").hidden = auditEntries.length === 0;
  const from = auditTotal ? auditOffset + 1 : 0;
  const through = auditOffset + auditEntries.length;
  $("#audit-result-count").textContent = `Showing ${from}–${through} of ${auditTotal} matching event${auditTotal === 1 ? "" : "s"}`;
  $("#audit-page-label").textContent = `Page ${Math.floor(auditOffset / auditLimit) + 1}`;
  $("#audit-prev").disabled = auditOffset === 0;
  $("#audit-next").disabled = through >= auditTotal || auditEntries.length === 0;
  const selector = $("#tamper-sequence");
  const selected = selector.value;
  selector.replaceChildren();
  for (const item of auditEntries) {
    const option = document.createElement("option");
    option.value = String(item.sequence);
    option.textContent = `#${item.sequence} · ${item.action}`;
    selector.append(option);
  }
  if (selected && [...selector.options].some((option) => option.value === selected)) selector.value = selected;

  for (const entry of auditEntries) {
    const row = document.createElement("tr");
    cell(row, entry.event_id, "student-id");
    cell(row, String(entry.sequence).padStart(4, "0"), "seq-cell");
    cell(row, formatTime(entry.timestamp));
    cell(row, entry.actor, "actor-cell");
    const action = cell(row, actionLabel(entry.action), `action-pill${entry.action === "marks_updated" ? " update" : ""}`);
    action.title = entry.action;
    const before = entry.before?.marks;
    const after = entry.after?.marks;
    const details = !entry.after
      ? `Record #${entry.record_id} · malformed event values`
      : entry.action === "student_created"
        ? `${entry.after.name || "Unknown student"} · ${entry.after.student_number || "No ID"} · ${after ?? "—"} marks`
        : `Record #${entry.record_id} · ${before ?? "—"} → ${after ?? "—"} marks`;
    cell(row, details, "change-text");
    const hash = cell(row, "", "hash-cell");
    const inspect = document.createElement("button");
    inspect.className = "inspect-button";
    inspect.type = "button";
    inspect.textContent = `${entry.entry_hash.slice(0, 10)}…`;
    inspect.setAttribute("aria-label", `Inspect audit event ${entry.event_id}, including its entry hash and HMAC`);
    inspect.addEventListener("click", () => inspectEvent(entry));
    hash.append(inspect);
    auditBody.append(row);
  }
}

async function loadAudit() {
  const form = $("#audit-filter-form");
  const values = new FormData(form);
  const params = new URLSearchParams({ limit: String(auditLimit), offset: String(auditOffset) });
  for (const name of ["action", "actor", "event_id", "record_id", "sequence_from", "sequence_to"]) {
    const value = String(values.get(name) || "").trim();
    if (value) params.set(name, value);
  }
  for (const name of ["start_at", "end_at"]) {
    const value = String(values.get(name) || "");
    if (value) params.set(name, new Date(value).toISOString());
  }
  const response = await fetch(`/api/audit?${params.toString()}`);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = payload.detail;
    const message = Array.isArray(detail) ? detail.map((item) => item.msg).join("; ") : detail;
    throw new Error(message || `Audit search failed (${response.status}).`);
  }
  auditEntries = payload;
  auditTotal = Number(response.headers.get("X-Total-Count") || auditEntries.length);
  renderAudit();
}

async function refresh() {
  const [studentResult, , status] = await Promise.all([
    api("/api/students"), loadAudit(), api("/api/status"),
  ]);
  students = studentResult;
  renderStudents();
  $("#demo-panel").hidden = !status.demo_tampering_enabled;
}

async function verify() {
  const button = $("#verify-button");
  button.disabled = true;
  button.textContent = "Verifying…";
  try {
    const result = await api("/api/audit/verify");
    verificationCurrent = true;
    const state = $("#integrity-state");
    const displayState = result.status === "empty" ? "empty" : (result.valid ? "valid" : "invalid");
    state.className = `status-value ${displayState}`;
    state.replaceChildren();
    const icon = document.createElement("span");
    icon.className = "state-icon";
    icon.textContent = result.status === "empty" ? "◌" : (result.valid ? "✓" : "!");
    const statusText = result.status === "empty" ? "Empty · no history" : (result.valid ? "Verified · intact" : `Failed · ${result.issues.length} finding(s)`);
    state.append(icon, document.createTextNode(statusText));
    $("#verified-at").textContent = new Date().toLocaleString([], { dateStyle: "medium", timeStyle: "short" });
    renderVerification(result);
    $("#download-report-button").disabled = false;
    showNotice(result.explanation, !result.valid);
  } catch (error) {
    verificationCurrent = false;
    $("#download-report-button").disabled = true;
    const state = $("#integrity-state");
    state.className = "status-value pending";
    state.replaceChildren(document.createTextNode("Verification unavailable"));
    $("#verification-panel").hidden = false;
    $("#verification-panel").className = "panel verification-panel empty";
    $("#verification-title").textContent = "Verification could not be completed";
    $("#verification-badge").textContent = "Unavailable";
    $("#verification-explanation").textContent = error.message;
    $("#verification-issues").hidden = true;
    showNotice(error.message, true);
  }
  finally {
    button.disabled = false;
    button.innerHTML = "<span>⟳</span> Verify integrity";
  }
}

async function downloadVerificationReport() {
  const button = $("#download-report-button");
  if (!verificationCurrent || button.disabled) return;
  button.disabled = true;
  button.textContent = "Preparing report…";
  try {
    const response = await fetch("/api/audit/verify/report", { headers: { Accept: "application/json" } });
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(payload.detail || `Report download failed (${response.status}).`);
    }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "verity-verification-report.json";
    document.body.append(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    showNotice("Verification report download started.");
  } catch (error) {
    showNotice(error.message || "Verification report could not be downloaded.", true);
  } finally {
    button.textContent = "Download Verification Report";
    button.disabled = !verificationCurrent;
  }
}

function renderVerification(result) {
  const panel = $("#verification-panel");
  panel.hidden = false;
  panel.className = `panel verification-panel ${result.status === "empty" ? "empty" : (result.valid ? "valid" : "failed")}`;
  $("#verification-title").textContent = result.status === "empty" ? "No audit history to verify" : (result.valid ? "Integrity checks passed" : "Integrity verification failed");
  $("#verification-badge").textContent = result.status === "empty" ? "Empty log" : (result.valid ? "Verified" : `${result.issues.length} finding(s)`);
  $("#verification-explanation").textContent = result.explanation;
  $("#last-valid-sequence").textContent = String(result.last_valid_sequence);
  const summary = result.verification_summary || {};
  $("#verified-prefix").textContent = `${summary.entries_in_verified_prefix ?? result.last_valid_sequence} of ${result.entries_checked} entries`;
  const checkpointIssue = (issue) => issue.check?.startsWith("checkpoint")
    || issue.target === "trusted_checkpoint"
    || issue.category.startsWith("checkpoint_")
    || issue.category === "invalid_checkpoint";
  const chainIssues = result.issues.filter((issue) => !checkpointIssue(issue));
  $("#chain-status").textContent = chainIssues.length
    ? `Failed · ${chainIssues.length} finding(s)`
    : (result.entries_checked ? "Passed · SHA-256 + HMAC" : "No entries to check");
  const checkpoint = result.checkpoint || { status: "not_configured" };
  const checkpointLabels = {
    match: `Trusted checkpoint matches at #${checkpoint.checkpoint_sequence}`,
    mismatch: "Trusted checkpoint mismatch",
    not_created: "No trusted checkpoint created",
    not_configured: "No trusted checkpoint configured",
    invalid: "Trusted checkpoint invalid",
  };
  $("#checkpoint-status").textContent = checkpointLabels[checkpoint.status]
    || `Checkpoint status: ${String(checkpoint.status || "unknown").replaceAll("_", " ")}`;
  $("#truncation-protection").textContent = checkpoint.status === "match"
    ? `Available · anchored at #${checkpoint.checkpoint_sequence}`
    : ["not_created", "not_configured"].includes(checkpoint.status)
      ? "Unavailable · no trusted checkpoint"
      : "Unavailable · checkpoint needs attention";
  const issuePanel = $("#verification-issues");
  issuePanel.replaceChildren();
  issuePanel.hidden = result.issues.length === 0;
  result.issues.forEach((issue, index) => {
    const line = document.createElement("div");
    line.className = "verification-issue";
    const heading = document.createElement("strong");
    const location = issue.target === "trusted_checkpoint"
      ? "Trusted checkpoint"
      : (issue.sequence !== null && issue.sequence !== undefined
        ? `Sequence ${issue.sequence}${issue.event_id ? ` · ${issue.event_id}` : ""}`
        : (issue.event_id || "Audit log"));
    const first = index === 0 ? "First failure · " : `Finding ${index + 1} · `;
    heading.textContent = `${first}${location} · ${issue.check || issue.category} · ${issue.code || issue.category}`;
    line.append(heading, document.createTextNode(issue.message));
    if (issue.expected_hash || issue.observed_hash) {
      const hashes = document.createElement("span");
      hashes.className = "verification-hashes";
      hashes.textContent = `Expected: ${issue.expected_hash || "—"} · Observed: ${issue.observed_hash || "—"}`;
      line.append(hashes);
    }
    issuePanel.append(line);
  });
}

$("#student-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const submit = form.querySelector("button[type=submit]");
  const data = new FormData(form);
  submit.disabled = true;
  try {
    await api("/api/students", { method: "POST", body: JSON.stringify({
      name: data.get("name"), student_number: data.get("student_number"), marks: Number(data.get("marks")),
    }) });
    markVerificationStale();
    showNotice("Student added; the creation event is now in the audit trail.");
    form.reset();
    form.elements.marks.value = "85";
    await refresh();
    await verify();
  } catch (error) { showNotice(error.message, true); }
  finally { submit.disabled = false; }
});

$("#verify-button").addEventListener("click", verify);
$("#download-report-button").addEventListener("click", downloadVerificationReport);
$("#audit-filter-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  auditOffset = 0;
  try { await loadAudit(); }
  catch (error) { showNotice(error.message, true); }
});
$("#audit-clear").addEventListener("click", async () => {
  $("#audit-filter-form").reset();
  auditOffset = 0;
  try { await loadAudit(); }
  catch (error) { showNotice(error.message, true); }
});
$("#audit-prev").addEventListener("click", async () => {
  auditOffset = Math.max(0, auditOffset - auditLimit);
  try { await loadAudit(); }
  catch (error) { showNotice(error.message, true); }
});
$("#audit-next").addEventListener("click", async () => {
  auditOffset += auditLimit;
  try { await loadAudit(); }
  catch (error) { auditOffset = Math.max(0, auditOffset - auditLimit); showNotice(error.message, true); }
});
$("#event-dialog-close").addEventListener("click", () => $("#event-dialog").close());
$("#event-dialog").addEventListener("click", (event) => {
  if (event.target === event.currentTarget) event.currentTarget.close();
});
$("#tamper-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const sequence = Number(new FormData(event.currentTarget).get("sequence"));
  if (!window.confirm(`DEVELOPMENT DEMO: alter audit entry #${sequence} and make verification fail?`)) return;
  const button = event.currentTarget.querySelector("button[type=submit]");
  button.disabled = true;
  try {
    const result = await api("/api/demo/tamper", { method: "POST", body: JSON.stringify({ sequence }) });
    showNotice(result.message, true);
    await refresh();
    await verify();
  } catch (error) { showNotice(error.message, true); }
  finally { button.disabled = false; }
});

refresh().catch((error) => {
  showNotice(`Could not load the dashboard: ${error.message}. Check that the server and HMAC key are configured.`, true);
  studentsBody.innerHTML = '<tr><td colspan="4" class="empty-cell">Dashboard unavailable. Check the server configuration.</td></tr>';
  auditBody.innerHTML = '<tr><td colspan="7" class="empty-cell">Audit history unavailable.</td></tr>';
}).finally(() => { $("#verify-button").disabled = false; });
