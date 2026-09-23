(() => {

    let cancelled = false;
    let results = [];

    function injectStyles() {

        if (document.getElementById("pgBulkStyles")) return;

        const style = document.createElement("style");
        style.id = "pgBulkStyles";

        style.textContent = `
            #pgBulkPanel {
                display:none;
                margin-top:22px;
                padding:24px;
                border:1px solid rgba(53,230,170,.25);
                border-radius:18px;
                background:rgba(4,35,28,.75);
                color:#fff;
            }

            .pg-bulk-head {
                margin-bottom:18px;
            }

            .pg-bulk-head h3 {
                margin:0 0 6px;
            }

            .pg-bulk-head p {
                margin:0;
                opacity:.65;
            }

            .pg-bulk-drop {
                padding:28px;
                border:1px dashed rgba(53,230,170,.45);
                border-radius:14px;
                text-align:center;
                cursor:pointer;
                background:rgba(53,230,170,.04);
            }

            .pg-bulk-drop.drag {
                background:rgba(53,230,170,.10);
            }

            .pg-bulk-actions {
                display:flex;
                gap:10px;
                flex-wrap:wrap;
                margin-top:16px;
            }

            .pg-bulk-btn {
                border:0;
                border-radius:9px;
                padding:10px 16px;
                cursor:pointer;
                font-weight:700;
            }

            .pg-bulk-start {
                background:#35e6aa;
                color:#03251d;
            }

            .pg-bulk-clear {
                background:rgba(255,255,255,.08);
                color:#fff;
            }

            .pg-bulk-cancel {
                background:rgba(255,188,80,.12);
                color:#ffc66d;
            }

            .pg-bulk-export {
                background:rgba(100,150,255,.13);
                color:#9bbaff;
            }

            .pg-bulk-btn:disabled {
                opacity:.35;
                cursor:not-allowed;
            }

            .pg-bulk-progress-wrap {
                margin-top:18px;
                display:none;
            }

            .pg-bulk-progress {
                height:10px;
                background:rgba(255,255,255,.08);
                border-radius:999px;
                overflow:hidden;
            }

            .pg-bulk-progress-bar {
                width:0%;
                height:100%;
                background:#35e6aa;
                transition:width .2s ease;
            }

            .pg-bulk-table-wrap {
                margin-top:20px;
                overflow-x:auto;
            }

            .pg-bulk-table {
                width:100%;
                border-collapse:collapse;
            }

            .pg-bulk-table th,
            .pg-bulk-table td {
                padding:12px;
                text-align:left;
                border-bottom:1px solid rgba(255,255,255,.06);
            }

            .pg-bulk-table th {
                opacity:.55;
                font-size:12px;
            }

            .pg-safe {
                color:#35e6aa;
                font-weight:700;
            }

            .pg-suspicious {
                color:#ffc857;
                font-weight:700;
            }

            .pg-phishing {
                color:#ff6b7a;
                font-weight:700;
            }

            .pg-error {
                color:#ff8585;
            }

            #pgBulkMessage {
                margin-top:14px;
                min-height:20px;
            }
        `;

        document.head.appendChild(style);
    }


    function findByText(text) {
        const wanted = text.toLowerCase();

        return [...document.querySelectorAll(
            "button, a, div, span"
        )].find(el =>
            el.children.length === 0 &&
            el.textContent.trim().toLowerCase() === wanted
        );
    }


    function findSingleScanner() {

        const button =
            [...document.querySelectorAll("button")]
            .find(btn =>
                btn.textContent.trim().toLowerCase()
                === "scan url"
            );

        if (!button) return null;

        return button.closest(
            "section, article, form, .card, .scanner-card, .scan-card"
        );
    }


    function normalizeURL(value) {

        let url = String(value || "")
            .trim()
            .replace(/^["']|["']$/g, "");

        if (!url) return null;

        if (
            !url.startsWith("http://")
            && !url.startsWith("https://")
        ) {
            url = "https://" + url;
        }

        try {
            const parsed = new URL(url);

            if (!parsed.hostname.includes(".")) {
                return null;
            }

            return parsed.href;

        } catch {
            return null;
        }
    }


    function extractURLs(text) {

        const output = [];

        const lines =
            text.split(/\r?\n/);

        for (const line of lines) {

            const parts =
                line.split(/[,\t;]+/);

            for (let part of parts) {

                part = part.trim();

                if (!part) continue;

                const direct =
                    part.match(
                        /https?:\/\/[^\s"'<>]+/i
                    );

                if (direct) {
                    const normalized =
                        normalizeURL(direct[0]);

                    if (normalized) {
                        output.push(normalized);
                    }

                    continue;
                }

                if (
                    /^[\w.-]+\.[a-z]{2,}(\/.*)?$/i
                    .test(part)
                ) {
                    const normalized =
                        normalizeURL(part);

                    if (normalized) {
                        output.push(normalized);
                    }
                }
            }
        }

        return [...new Set(output)]
            .slice(0, 500);
    }


    function makePanel(anchor) {

        if (
            document.getElementById(
                "pgBulkPanel"
            )
        ) {
            return document.getElementById(
                "pgBulkPanel"
            );
        }

        const panel =
            document.createElement("section");

        panel.id = "pgBulkPanel";

        panel.innerHTML = `
            <div class="pg-bulk-head">
                <h3>📁 Bulk URL Scanner</h3>
                <p>
                    Upload TXT or CSV file.
                    Maximum 500 unique URLs.
                </p>
            </div>

            <div
                id="pgBulkDrop"
                class="pg-bulk-drop"
            >
                <strong>
                    Drop TXT / CSV file here
                </strong>

                <div style="margin-top:6px;opacity:.6">
                    or click to choose file
                </div>

                <input
                    id="pgBulkFile"
                    type="file"
                    accept=".txt,.csv,text/plain,text/csv"
                    hidden
                >
            </div>

            <div
                id="pgBulkFileInfo"
                style="margin-top:12px;opacity:.75"
            >
                No file selected
            </div>

            <div class="pg-bulk-actions">

                <button
                    id="pgBulkStart"
                    class="pg-bulk-btn pg-bulk-start"
                    disabled
                >
                    Start Bulk Scan
                </button>

                <button
                    id="pgBulkCancel"
                    class="pg-bulk-btn pg-bulk-cancel"
                    disabled
                >
                    Cancel
                </button>

                <button
                    id="pgBulkClear"
                    class="pg-bulk-btn pg-bulk-clear"
                >
                    Clear
                </button>

                <button
                    id="pgBulkExport"
                    class="pg-bulk-btn pg-bulk-export"
                    disabled
                >
                    Export CSV
                </button>

            </div>

            <div
                id="pgBulkMessage"
            ></div>

            <div
                id="pgBulkProgressWrap"
                class="pg-bulk-progress-wrap"
            >

                <div
                    id="pgBulkProgressText"
                    style="margin-bottom:8px"
                >
                    0 / 0
                </div>

                <div class="pg-bulk-progress">
                    <div
                        id="pgBulkProgressBar"
                        class="pg-bulk-progress-bar"
                    ></div>
                </div>

            </div>

            <div class="pg-bulk-table-wrap">

                <table class="pg-bulk-table">

                    <thead>
                        <tr>
                            <th>#</th>
                            <th>URL</th>
                            <th>Status</th>
                            <th>Risk</th>
                            <th>ML</th>
                        </tr>
                    </thead>

                    <tbody id="pgBulkBody">
                    </tbody>

                </table>

            </div>
        `;

        const parent =
            anchor.parentElement;

        if (parent) {
            parent.insertAdjacentElement(
                "afterend",
                panel
            );
        } else {
            document.querySelector("main")
                ?.appendChild(panel);
        }

        return panel;
    }


    function statusClass(status) {

        if (status === "SAFE") {
            return "pg-safe";
        }

        if (status === "SUSPICIOUS") {
            return "pg-suspicious";
        }

        if (status === "PHISHING") {
            return "pg-phishing";
        }

        return "pg-error";
    }


    function renderResults() {

        const body =
            document.getElementById(
                "pgBulkBody"
            );

        if (!body) return;

        body.innerHTML =
            results.map((row, index) => `
                <tr>
                    <td>${index + 1}</td>

                    <td style="max-width:430px;word-break:break-all">
                        ${row.url}
                    </td>

                    <td class="${statusClass(row.status)}">
                        ${row.status}
                    </td>

                    <td>
                        ${
                            row.risk_score !== null
                            ? row.risk_score + "%"
                            : "—"
                        }
                    </td>

                    <td>
                        ${row.ml_prediction || "—"}
                    </td>
                </tr>
            `).join("");
    }


    function delay(ms) {
        return new Promise(
            resolve =>
                setTimeout(resolve, ms)
        );
    }


    async function scanOne(url) {

        const response =
            await fetch(
                "/api/scan",
                {
                    method: "POST",
                    credentials: "same-origin",
                    headers: {
                        "Content-Type":
                            "application/json"
                    },
                    body: JSON.stringify({
                        url
                    })
                }
            );

        if (response.status === 429) {

            await delay(2000);

            return scanOne(url);
        }

        let data;

        try {
            data = await response.json();
        } catch {
            throw new Error(
                "Invalid server response"
            );
        }

        if (!response.ok) {
            throw new Error(
                data.error ||
                `HTTP ${response.status}`
            );
        }

        return data;
    }


    async function startScan(urls) {

        cancelled = false;
        results = [];

        const start =
            document.getElementById(
                "pgBulkStart"
            );

        const cancel =
            document.getElementById(
                "pgBulkCancel"
            );

        const exportBtn =
            document.getElementById(
                "pgBulkExport"
            );

        const wrap =
            document.getElementById(
                "pgBulkProgressWrap"
            );

        const progress =
            document.getElementById(
                "pgBulkProgressBar"
            );

        const progressText =
            document.getElementById(
                "pgBulkProgressText"
            );

        const message =
            document.getElementById(
                "pgBulkMessage"
            );

        start.disabled = true;
        cancel.disabled = false;
        exportBtn.disabled = true;

        wrap.style.display = "block";

        message.textContent =
            "Scanning URLs...";

        for (
            let i = 0;
            i < urls.length;
            i++
        ) {

            if (cancelled) {
                message.textContent =
                    "⚠️ Bulk scan cancelled.";
                break;
            }

            const url = urls[i];

            try {

                const data =
                    await scanOne(url);

                results.push({
                    url: data.url || url,
                    status:
                        data.status || "UNKNOWN",
                    risk_score:
                        data.risk_score ?? null,
                    ml_prediction:
                        data.ml_prediction || ""
                });

            } catch (error) {

                results.push({
                    url,
                    status: "ERROR",
                    risk_score: null,
                    ml_prediction: "",
                    error: error.message
                });
            }

            const done = i + 1;

            const percent =
                Math.round(
                    (done / urls.length) * 100
                );

            progress.style.width =
                percent + "%";

            progressText.textContent =
                `${done} / ${urls.length} (${percent}%)`;

            renderResults();

            /*
             Small delay avoids hammering
             Flask/rate limiter.
            */
            await delay(250);
        }

        start.disabled = false;
        cancel.disabled = true;

        if (results.length) {
            exportBtn.disabled = false;
        }

        if (!cancelled) {
            message.textContent =
                `✅ Bulk scan finished. ${results.length} URLs processed.`;
        }
    }


    function exportCSV() {

        if (!results.length) return;

        const rows = [
            [
                "URL",
                "Status",
                "Risk Score",
                "ML Prediction"
            ],
            ...results.map(row => [
                row.url,
                row.status,
                row.risk_score ?? "",
                row.ml_prediction || ""
            ])
        ];

        const safeCell = value => {

            let text =
                String(value ?? "");

            /*
             Prevent spreadsheet formula injection.
            */
            if (/^[=+\-@]/.test(text)) {
                text = "'" + text;
            }

            return '"' +
                text.replaceAll('"', '""') +
                '"';
        };

        const csv =
            rows
                .map(row =>
                    row.map(safeCell).join(",")
                )
                .join("\n");

        const blob =
            new Blob(
                [csv],
                {
                    type:
                        "text/csv;charset=utf-8"
                }
            );

        const url =
            URL.createObjectURL(blob);

        const a =
            document.createElement("a");

        a.href = url;
        a.download =
            "phishguard-bulk-scan.csv";

        a.click();

        URL.revokeObjectURL(url);
    }


    function setupPanel(
        panel,
        bulkTab,
        singleTab
    ) {

        if (
            panel.dataset.ready === "1"
        ) {
            return;
        }

        panel.dataset.ready = "1";

        const input =
            panel.querySelector(
                "#pgBulkFile"
            );

        const drop =
            panel.querySelector(
                "#pgBulkDrop"
            );

        const info =
            panel.querySelector(
                "#pgBulkFileInfo"
            );

        const start =
            panel.querySelector(
                "#pgBulkStart"
            );

        const cancel =
            panel.querySelector(
                "#pgBulkCancel"
            );

        const clear =
            panel.querySelector(
                "#pgBulkClear"
            );

        const exportBtn =
            panel.querySelector(
                "#pgBulkExport"
            );

        let urls = [];


        async function handleFile(file) {

            if (!file) return;

            const lower =
                file.name.toLowerCase();

            if (
                !lower.endsWith(".txt")
                && !lower.endsWith(".csv")
            ) {
                info.textContent =
                    "❌ Only TXT or CSV files are supported.";

                start.disabled = true;
                return;
            }

            if (
                file.size >
                5 * 1024 * 1024
            ) {
                info.textContent =
                    "❌ File is larger than 5 MB.";

                start.disabled = true;
                return;
            }

            const text =
                await file.text();

            urls =
                extractURLs(text);

            info.textContent =
                `${file.name} — ${urls.length} valid unique URLs found`;

            start.disabled =
                urls.length === 0;
        }


        drop.addEventListener(
            "click",
            () => input.click()
        );


        input.addEventListener(
            "change",
            () =>
                handleFile(
                    input.files[0]
                )
        );


        drop.addEventListener(
            "dragover",
            event => {

                event.preventDefault();
                drop.classList.add("drag");
            }
        );


        drop.addEventListener(
            "dragleave",
            () =>
                drop.classList.remove(
                    "drag"
                )
        );


        drop.addEventListener(
            "drop",
            event => {

                event.preventDefault();

                drop.classList.remove(
                    "drag"
                );

                handleFile(
                    event.dataTransfer.files[0]
                );
            }
        );


        start.addEventListener(
            "click",
            () => {

                if (urls.length) {
                    startScan(urls);
                }
            }
        );


        cancel.addEventListener(
            "click",
            () => {
                cancelled = true;
            }
        );


        clear.addEventListener(
            "click",
            () => {

                cancelled = true;
                urls = [];
                results = [];

                input.value = "";

                info.textContent =
                    "No file selected";

                panel.querySelector(
                    "#pgBulkBody"
                ).innerHTML = "";

                panel.querySelector(
                    "#pgBulkProgressWrap"
                ).style.display = "none";

                panel.querySelector(
                    "#pgBulkMessage"
                ).textContent = "";

                start.disabled = true;
                exportBtn.disabled = true;
            }
        );


        exportBtn.addEventListener(
            "click",
            exportCSV
        );


        bulkTab.addEventListener(
            "click",
            event => {

                event.preventDefault();
                event.stopImmediatePropagation();

                panel.style.display =
                    "block";

                const scanner =
                    findSingleScanner();

                if (scanner) {
                    scanner.dataset.pgOldDisplay =
                        scanner.style.display || "";

                    scanner.style.display =
                        "none";
                }

                bulkTab.classList.add(
                    "active"
                );

                if (singleTab) {
                    singleTab.classList.remove(
                        "active"
                    );
                }

            },
            true
        );


        if (singleTab) {

            singleTab.addEventListener(
                "click",
                () => {

                    panel.style.display =
                        "none";

                    const scanner =
                        findSingleScanner();

                    if (scanner) {
                        scanner.style.display =
                            scanner.dataset.pgOldDisplay
                            || "";
                    }

                    singleTab.classList.add(
                        "active"
                    );

                    bulkTab.classList.remove(
                        "active"
                    );
                },
                true
            );
        }
    }


    function init() {

        injectStyles();

        const bulkTab =
            findByText(
                "Bulk file scan"
            );

        if (!bulkTab) {
            return;
        }

        const singleTab =
            findByText(
                "Single URL"
            );

        const panel =
            makePanel(bulkTab);

        setupPanel(
            panel,
            bulkTab,
            singleTab
        );

        console.log(
            "✅ PhishGuard Bulk Scanner connected"
        );
    }


    document.addEventListener(
        "DOMContentLoaded",
        init
    );

    setTimeout(init, 500);
    setTimeout(init, 1500);

})();
