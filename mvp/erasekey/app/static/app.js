const runButton = document.querySelector("#run-demo");
const resetButton = document.querySelector("#reset-view");
const timeline = document.querySelector("#timeline");
const resultsTitle = document.querySelector("#results-title");
const scenarioMeta = document.querySelector("#scenario-meta");
const verificationGrid = document.querySelector("#verification-grid");
const technicalDetails = document.querySelector("#technical-details");
const errorPanel = document.querySelector("#error-panel");
const errorMessage = document.querySelector("#error-message");

const phaseDescriptions = {
  encrypted: "The subject key decrypts the sample record.",
  deleted: "The wrapped key is gone; ciphertext remains.",
  restored: "Old database state brings the wrapped key back.",
  reconciled: "The signed receipt destroys the restored key.",
};

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function renderTimeline(phases) {
  timeline.innerHTML = phases
    .map((phase, index) => {
      const isWarning = phase.phase === "restored";
      const visibility = phase.payload_visible
        ? "Payload readable"
        : "Payload unavailable";
      return `
        <article class="phase-card ${isWarning ? "warning" : "success"}">
          <span class="phase-number">${index + 1}</span>
          <h3 class="phase-label">${escapeHtml(phase.label)}</h3>
          <p class="phase-state">${escapeHtml(phaseDescriptions[phase.phase] || phase.erase_status)}</p>
          <span class="phase-visibility">${escapeHtml(visibility)}</span>
        </article>
      `;
    })
    .join("");
}

function setText(selector, value) {
  document.querySelector(selector).textContent = value;
}

function renderVerification(data) {
  const receipt = data.receipt_verification;
  const audit = data.audit_verification;
  const reconciliation = data.reconciliation;
  const evidence = data.evidence.evidence;
  const deletionReceipt = evidence.deletion_receipt || {};

  setText("#receipt-title", receipt.ok ? "Verified" : "Invalid");
  setText(
    "#receipt-detail",
    `${receipt.receipt_count} signed receipt${receipt.receipt_count === 1 ? "" : "s"} checked.`
  );
  setText("#receipt-icon", receipt.ok ? "✓" : "!");

  setText("#audit-title", audit.ok ? "Chain intact" : "Chain invalid");
  setText(
    "#audit-detail",
    `${audit.verified_count} audit event${audit.verified_count === 1 ? "" : "s"} verified.`
  );
  setText("#audit-icon", audit.ok ? "✓" : "!");

  setText("#recovery-title", "Key erased again");
  setText(
    "#recovery-detail",
    `${reconciliation.re_erased_key_ids.length} restored key removed using the external receipt.`
  );

  setText("#request-id", data.deletion_request_id);
  setText("#subject-ref", deletionReceipt.subject_ref || "not available");
  setText("#receipt-id", deletionReceipt.receipt_id || "not available");
  setText("#audit-head", audit.head_hash || "not available");

  verificationGrid.hidden = false;
  technicalDetails.hidden = false;
}

function setLoading(isLoading) {
  runButton.disabled = isLoading;
  runButton.querySelector("span:first-child").textContent = isLoading
    ? "Running the scenario..."
    : "Run another scenario";
}

function resetResults() {
  timeline.innerHTML = [1, 2, 3, 4]
    .map(
      (number) => `
        <article class="phase-card placeholder">
          <span class="phase-number">${number}</span>
          <p>Waiting for scenario</p>
        </article>
      `
    )
    .join("");
  resultsTitle.textContent = "Ready to run";
  scenarioMeta.textContent = "Four real state transitions will appear here.";
  verificationGrid.hidden = true;
  technicalDetails.hidden = true;
  technicalDetails.open = false;
  errorPanel.hidden = true;
  resetButton.hidden = true;
  runButton.querySelector("span:first-child").textContent = "Run restore scenario";
}

async function runScenario() {
  setLoading(true);
  errorPanel.hidden = true;
  verificationGrid.hidden = true;
  technicalDetails.hidden = true;
  resultsTitle.textContent = "Running the restore experiment";
  scenarioMeta.textContent = "Creating encrypted data and exercising the real deletion path.";

  try {
    const response = await fetch("/demo/restore-scenario", { method: "POST" });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.detail || "The server rejected the demo request.");
    }

    renderTimeline(data.timeline);
    renderVerification(data);
    resultsTitle.textContent = "Deletion survived the stale restore";
    scenarioMeta.textContent =
      `Scenario ${data.scenario_id} used subject ${data.subject_id}.`;
    resetButton.hidden = false;
    document.querySelector("#results").scrollIntoView({
      behavior: "smooth",
      block: "start",
    });
  } catch (error) {
    resultsTitle.textContent = "Scenario stopped";
    scenarioMeta.textContent = "No result was hidden; review the error below.";
    errorMessage.textContent = error.message;
    errorPanel.hidden = false;
  } finally {
    setLoading(false);
  }
}

runButton.addEventListener("click", runScenario);
resetButton.addEventListener("click", resetResults);
