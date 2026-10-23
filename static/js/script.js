"use strict";

const form = document.getElementById("scan-form");
const targetInput = document.getElementById("target-url");
const authorizationInput = document.getElementById("authorization");
const scanButton = document.getElementById("scan-button");
const buttonLabel = scanButton.querySelector(".button-label");
const targetError = document.getElementById("target-error");
const state = document.getElementById("scan-state");
const tableWrap = document.getElementById("findings-table-wrap");
const findingsBody = document.getElementById("findings-body");
const searchInput = document.getElementById("finding-search");
const severityFilter = document.getElementById("severity-filter");
const findingsControls = document.getElementById("findings-controls");
const filterEmpty = document.getElementById("filter-empty");
const headersPanel = document.getElementById("headers-panel");
const headersBody = document.getElementById("headers-body");
const robotsPanel = document.getElementById("robots-panel");
const robotsList = document.getElementById("robots-list");
const menuToggle = document.getElementById("menu-toggle");
const sidebar = document.getElementById("sidebar");
const mobileOverlay = document.getElementById("mobile-overlay");

let currentFindings = [];
let sortState = { key: "severity", ascending: true };

function setState(kind, title, message, icon) {
    state.className = `scan-state ${kind}`;
    state.replaceChildren();

    const iconElement = document.createElement("span");
    iconElement.className = "state-icon";
    iconElement.setAttribute("aria-hidden", "true");
    iconElement.textContent = icon;

    const heading = document.createElement("h4");
    heading.textContent = title;

    const description = document.createElement("p");
    description.textContent = message;

    state.append(iconElement, heading, description);
    state.hidden = false;
    tableWrap.hidden = true;
}

function setScanMetadata(targetUrl, status, message) {
    const panel = document.getElementById("scan-summary-panel");
    const target = document.getElementById("result-target");
    const statusBadge = document.getElementById("result-status");
    const error = document.getElementById("result-error");

    panel.hidden = false;
    target.textContent = targetUrl || "—";
    target.title = targetUrl || "";
    statusBadge.textContent = status;
    statusBadge.className = `scan-status-badge scan-status-${status}`;
    error.textContent = message || "";
    error.hidden = !message;
}

function clearSummary() {
    document.getElementById("scan-summary-panel").hidden = true;
    document.getElementById("pages-value").textContent = "—";
    document.getElementById("findings-value").textContent = "—";
    document.getElementById("categories-value").textContent = "—";
    document.getElementById("warnings-value").textContent = "—";
    document.getElementById("finding-count").textContent = "—";
    findingsBody.replaceChildren();
    headersBody.replaceChildren();
    headersPanel.hidden = true;
    robotsList.replaceChildren();
    robotsPanel.hidden = true;
    findingsControls.hidden = true;
    filterEmpty.hidden = true;
    currentFindings = [];
}

function severityClass(severity) {
    switch (String(severity).toLowerCase()) {
        case "critical": return "severity-critical";
        case "high": return "severity-high";
        case "medium": return "severity-medium";
        case "low": return "severity-low";
        default: return "severity-unknown";
    }
}

function createCell(text) {
    const cell = document.createElement("td");
    cell.textContent = text == null || text === "" ? "—" : String(text);
    return cell;
}

function makeDetails(finding) {
    const detailsCell = document.createElement("td");
    const details = document.createElement("details");
    details.className = "finding-details";
    const summary = document.createElement("summary");
    summary.textContent = "View details";
    details.append(summary);

    const content = document.createElement("div");
    content.className = "finding-detail-content";

    if (finding.description) {
        const explanation = document.createElement("p");
        const label = document.createElement("strong");
        label.textContent = "Technical explanation: ";
        explanation.append(label, document.createTextNode(String(finding.description)));
        content.append(explanation);
    }

    if (finding.recommendation) {
        const recommendation = document.createElement("p");
        const label = document.createElement("strong");
        label.textContent = "Remediation guidance: ";
        recommendation.append(label, document.createTextNode(String(finding.recommendation)));
        content.append(recommendation);
    }

    if (finding.technical_details && typeof finding.technical_details === "object") {
        const list = document.createElement("dl");
        list.className = "technical-details";
        const labels = {
            cvss: "CVSS",
            parameter: "Parameter",
            payload: "Test payload",
            matching_error: "Matching error signature",
            header: "Header"
        };
        for (const [key, labelText] of Object.entries(labels)) {
            const value = finding.technical_details[key];
            if (value == null || value === "") continue;
            const term = document.createElement("dt");
            term.textContent = labelText;
            const description = document.createElement("dd");
            description.textContent = String(value);
            list.append(term, description);
        }
        if (list.childElementCount) content.append(list);
    }

    if (!content.childElementCount) {
        const unavailable = document.createElement("p");
        unavailable.textContent = "The scanner did not return additional technical details or remediation guidance.";
        content.append(unavailable);
    }

    details.append(content);
    detailsCell.append(details);
    return detailsCell;
}

function makeFindingRow(finding) {
    const row = document.createElement("tr");
    const severityCell = document.createElement("td");
    const severityBadge = document.createElement("span");
    severityBadge.className = `severity-badge ${severityClass(finding.severity)}`;
    severityBadge.textContent = finding.severity || "—";
    severityCell.append(severityBadge);

    const category = createCell(finding.category);
    category.classList.add("finding-category");
    const urlCell = createCell(finding.affected_url);
    urlCell.classList.add("affected-url-cell");
    if (finding.affected_url) {
        const copyButton = document.createElement("button");
        copyButton.type = "button";
        copyButton.className = "copy-url-button";
        copyButton.textContent = "Copy URL";
        copyButton.setAttribute("aria-label", `Copy affected URL ${finding.affected_url}`);
        copyButton.addEventListener("click", async () => {
            try {
                await navigator.clipboard.writeText(String(finding.affected_url));
                copyButton.textContent = "Copied";
                window.setTimeout(() => { copyButton.textContent = "Copy URL"; }, 1600);
            } catch {
                copyButton.textContent = "Copy unavailable";
            }
        });
        urlCell.append(copyButton);
    }

    const explanation = createCell(finding.description);
    explanation.classList.add("finding-explanation");
    row.append(severityCell, category, urlCell, explanation, makeDetails(finding));
    return row;
}

function severityOrder(value) {
    const order = ["critical", "high", "medium", "low", "info", "informational"];
    const normalized = String(value || "").toLowerCase();
    const index = order.indexOf(normalized);
    return index < 0 ? order.length : index;
}

function compareFindings(first, second, key) {
    const firstValue = first[key];
    const secondValue = second[key];
    if (key === "severity") {
        const difference = severityOrder(firstValue) - severityOrder(secondValue);
        if (difference) return difference;
    }
    return String(firstValue || "").localeCompare(String(secondValue || ""), undefined, {
        numeric: true,
        sensitivity: "base"
    });
}

function updateSortHeaders() {
    document.querySelectorAll(".sort-button").forEach((button) => {
        const header = button.closest("th");
        const isActive = button.dataset.sort === sortState.key;
        header.setAttribute(
            "aria-sort",
            isActive ? (sortState.ascending ? "ascending" : "descending") : "none"
        );
        button.querySelector("span").textContent = isActive
            ? (sortState.ascending ? "↑" : "↓")
            : "";
    });
}

function renderFindings() {
    const query = searchInput.value.trim().toLowerCase();
    const selectedSeverity = severityFilter.value;
    const filtered = currentFindings.filter((finding) => {
        const matchesSeverity = !selectedSeverity || finding.severity === selectedSeverity;
        const searchable = [
            finding.severity,
            finding.category,
            finding.affected_url,
            finding.description,
            ...(finding.technical_details ? Object.values(finding.technical_details) : [])
        ].filter(Boolean).join(" ").toLowerCase();
        return matchesSeverity && searchable.includes(query);
    });

    const groups = new Map();
    for (const finding of filtered) {
        const key = finding.severity || "";
        if (!groups.has(key)) groups.set(key, []);
        groups.get(key).push(finding);
    }

    const groupKeys = [...groups.keys()].sort((first, second) => {
        const comparison = compareFindings({ severity: first }, { severity: second }, "severity");
        return sortState.ascending ? comparison : -comparison;
    });
    const rows = [];
    for (const severity of groupKeys) {
        const group = groups.get(severity);
        group.sort((first, second) => {
            const comparison = compareFindings(first, second, sortState.key);
            return sortState.ascending ? comparison : -comparison;
        });

        const groupRow = document.createElement("tr");
        groupRow.className = "severity-group-row";
        const groupHeading = document.createElement("th");
        groupHeading.scope = "rowgroup";
        groupHeading.colSpan = 5;
        groupHeading.textContent = severity || "Severity not provided";
        groupRow.append(groupHeading);
        rows.push(groupRow, ...group.map(makeFindingRow));
    }

    findingsBody.replaceChildren(...rows);
    document.getElementById("finding-count").textContent =
        filtered.length === currentFindings.length
            ? String(currentFindings.length)
            : `${filtered.length} / ${currentFindings.length}`;
    tableWrap.hidden = filtered.length === 0;
    filterEmpty.hidden = filtered.length !== 0 || currentFindings.length === 0;
    state.hidden = currentFindings.length !== 0;
    updateSortHeaders();
}

function renderHeaderResults(headers) {
    if (!Array.isArray(headers) || headers.length === 0) {
        const row = document.createElement("tr");
        const message = document.createElement("td");
        message.colSpan = 3;
        message.textContent = "No security header results were returned by the scanner.";
        row.append(message);
        headersBody.replaceChildren(row);
        headersPanel.hidden = false;
        return;
    }

    const rows = headers.map((header) => {
        const row = document.createElement("tr");
        const name = createCell(header.name);
        const status = createCell(header.status);
        status.className = header.status === "present" ? "header-present" : "header-missing";
        row.append(name, status, createCell(header.value));
        return row;
    });
    headersBody.replaceChildren(...rows);
    headersPanel.hidden = false;
}

function renderResults(result) {
    const findings = Array.isArray(result.findings) ? result.findings : [];
    currentFindings = findings;
    sortState = { key: "severity", ascending: true };

    const categories = new Set(findings.map((finding) => finding.category).filter(Boolean));
    const lowSeverityCount = findings.filter(
        (finding) => String(finding.severity).toLowerCase() === "low"
    ).length;
    document.getElementById("pages-value").textContent =
        Number.isInteger(result.pages_scanned) ? String(result.pages_scanned) : "—";
    document.getElementById("findings-value").textContent = String(findings.length);
    document.getElementById("categories-value").textContent = String(categories.size);
    document.getElementById("warnings-value").textContent = String(lowSeverityCount);
    document.getElementById("results-caption").textContent =
        result.scan_status === "partial" ? "Scan completed with incomplete results." : "Scan request completed.";
    document.getElementById("findings-subtitle").textContent = findings.length
        ? "Potential findings returned by the scanner. No finding is confirmed solely by this automated check."
        : "No findings were returned by the configured checks; this does not prove the target is completely secure.";

    setScanMetadata(result.target_url, result.scan_status, result.error);
    renderHeaderResults(result.security_headers);

    severityFilter.replaceChildren(new Option("All severities", ""));
    const severities = [...new Set(findings.map((finding) => finding.severity).filter(Boolean))]
        .sort((first, second) => compareFindings({ severity: first }, { severity: second }, "severity"));
    for (const severity of severities) {
        severityFilter.add(new Option(severity, severity));
    }

    const paths = Array.isArray(result.robots_paths) ? result.robots_paths : [];
    if (paths.length) {
        robotsList.replaceChildren(...paths.map((path) => {
            const item = document.createElement("li");
            item.textContent = String(path);
            return item;
        }));
        robotsPanel.hidden = false;
    } else {
        robotsPanel.hidden = true;
    }

    if (findings.length) {
        findingsControls.hidden = false;
        renderFindings();
    } else {
        findingsControls.hidden = true;
        findingsBody.replaceChildren();
        tableWrap.hidden = true;
        filterEmpty.hidden = true;
        state.hidden = false;
        setState(
            result.scan_status === "partial" ? "partial" : "success",
            result.scan_status === "partial" ? "Scan was incomplete" : "No findings returned",
            result.error || "No findings were returned by the configured checks. This does not prove the target is completely secure.",
            result.scan_status === "partial" ? "!" : "✓"
        );
    }
}

function renderFailedResponse(result) {
    const findings = Array.isArray(result.findings) ? result.findings : [];
    document.getElementById("pages-value").textContent =
        Number.isInteger(result.pages_scanned) ? String(result.pages_scanned) : "—";
    document.getElementById("findings-value").textContent = String(findings.length);
    document.getElementById("categories-value").textContent =
        String(new Set(findings.map((finding) => finding.category).filter(Boolean)).size);
    document.getElementById("warnings-value").textContent = String(findings.filter(
        (finding) => String(finding.severity).toLowerCase() === "low"
    ).length);
    document.getElementById("finding-count").textContent = String(findings.length);
    document.getElementById("findings-subtitle").textContent =
        "The scan failed; any returned findings may be incomplete.";
    document.getElementById("results-caption").textContent = "The scan did not complete.";
    setScanMetadata(
        result.target_url || targetInput.value.trim(),
        result.scan_status || "failed",
        result.error || "The scanner did not return a more specific error."
    );
    renderHeaderResults(result.security_headers);

    if (findings.length) {
        currentFindings = findings;
        findingsControls.hidden = false;
        renderFindings();
    } else {
        findingsControls.hidden = true;
        tableWrap.hidden = true;
        setState(
            "failure",
            "Scan failed",
            result.error || "The scanner did not return a more specific error.",
            "!"
        );
    }
}

function setLoading(loading) {
    scanButton.disabled = loading;
    scanButton.classList.toggle("is-loading", loading);
    buttonLabel.textContent = loading ? "Scanning…" : "Scan website";
    targetInput.disabled = loading;
    authorizationInput.disabled = loading;
}

function closeNavigation() {
    sidebar.classList.remove("is-open");
    mobileOverlay.classList.remove("is-visible");
    mobileOverlay.hidden = true;
    menuToggle.setAttribute("aria-expanded", "false");
    menuToggle.setAttribute("aria-label", "Open navigation");
}

menuToggle.addEventListener("click", () => {
    const isOpen = sidebar.classList.toggle("is-open");
    mobileOverlay.hidden = !isOpen;
    mobileOverlay.classList.toggle("is-visible", isOpen);
    menuToggle.setAttribute("aria-expanded", String(isOpen));
    menuToggle.setAttribute("aria-label", isOpen ? "Close navigation" : "Open navigation");
});

mobileOverlay.addEventListener("click", closeNavigation);
sidebar.querySelectorAll(".nav-link").forEach((link) => link.addEventListener("click", closeNavigation));
searchInput.addEventListener("input", renderFindings);
severityFilter.addEventListener("change", renderFindings);

document.querySelectorAll(".sort-button").forEach((button) => {
    button.addEventListener("click", () => {
        const key = button.dataset.sort;
        if (sortState.key === key) {
            sortState.ascending = !sortState.ascending;
        } else {
            sortState = { key, ascending: true };
        }
        renderFindings();
    });
});

targetInput.addEventListener("input", () => {
    targetError.hidden = true;
    targetError.textContent = "";
    targetInput.removeAttribute("aria-invalid");
});

form.addEventListener("submit", async (event) => {
    event.preventDefault();
    targetError.hidden = true;
    targetError.textContent = "";
    targetInput.removeAttribute("aria-invalid");

    if (!targetInput.value.trim() || !targetInput.checkValidity()) {
        targetError.textContent = "Enter a valid HTTP or HTTPS URL for an allowlisted host.";
        targetError.hidden = false;
        targetInput.setAttribute("aria-invalid", "true");
        targetInput.focus();
        return;
    }

    if (!authorizationInput.checked) {
        targetError.textContent = "Confirm that you are authorized to scan this target.";
        targetError.hidden = false;
        authorizationInput.focus();
        return;
    }

    clearSummary();
    document.getElementById("results-caption").textContent = "Scan in progress; waiting for the scanner response.";
    document.getElementById("findings-subtitle").textContent = "The scanner is running. This may take a little while.";
    setState("loading", "Scan in progress", "The scanner is crawling the target and running its configured checks. Progress updates are not provided by the backend.", "◌");
    setLoading(true);

    try {
        const response = await fetch("/api/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json", "Accept": "application/json" },
            body: JSON.stringify({ url: targetInput.value.trim(), authorized: authorizationInput.checked })
        });

        let payload;
        try {
            payload = await response.json();
        } catch {
            throw new Error("The server returned an unreadable response.");
        }

        if (payload && payload.scan_status === "failed") {
            renderFailedResponse(payload);
            return;
        }

        if (!response.ok) {
            if (payload && payload.scan_status === "rejected") {
                document.getElementById("results-caption").textContent = "The scan request was rejected.";
                document.getElementById("findings-subtitle").textContent = "Review the configuration or request error below.";
                setScanMetadata(
                    targetInput.value.trim(),
                    "rejected",
                    typeof payload.error === "string" ? payload.error : `Request rejected (${response.status}).`
                );
                setState(
                    "failure",
                    "Request rejected",
                    typeof payload.error === "string" ? payload.error : `Request rejected (${response.status}).`,
                    "!"
                );
                return;
            }
            throw new Error(payload && typeof payload.error === "string"
                ? payload.error
                : `The scan request failed with status ${response.status}.`);
        }

        if (!payload || !Array.isArray(payload.findings)) {
            throw new Error("The server response did not contain scan findings.");
        }
        if (!["completed", "partial"].includes(payload.scan_status)) {
            throw new Error("The server returned an unrecognized scan status.");
        }

        renderResults(payload);
    } catch (error) {
        clearSummary();
        document.getElementById("results-caption").textContent = "The scan did not complete.";
        document.getElementById("findings-subtitle").textContent = "Review the error and try again.";
        setScanMetadata(targetInput.value.trim(), "failed", error instanceof Error ? error.message : "An unexpected error occurred.");
        setState("failure", "Scan failed", error instanceof Error ? error.message : "An unexpected error occurred.", "!");
    } finally {
        setLoading(false);
    }
});
