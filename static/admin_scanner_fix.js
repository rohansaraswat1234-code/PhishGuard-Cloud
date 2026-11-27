(() => {

    function findScanButton() {
        return [...document.querySelectorAll("button")]
            .find(btn =>
                btn.textContent.trim().toLowerCase()
                === "scan url"
            );
    }

    function findURLInput(button) {

        const area =
            button.closest(
                "form, section, .card, .scanner-card, .scan-card, main"
            ) || document;

        const inputs =
            [...area.querySelectorAll(
                'input[type="url"], input[type="text"]'
            )];

        return (
            inputs.find(input =>
                /url|link/i.test(
                    (input.placeholder || "") +
                    " " +
                    (input.name || "") +
                    " " +
                    (input.id || "")
                )
            )
            || inputs[0]
            || null
        );
    }

    function getResultBox(button) {

        let box =
            document.getElementById(
                "pgScannerFixResult"
            );

        if (box) return box;

        box = document.createElement("div");

        box.id = "pgScannerFixResult";

        box.style.cssText = `
            margin-top:18px;
            padding:18px;
            border:1px solid rgba(53,230,170,.25);
            border-radius:14px;
            background:rgba(4,35,28,.75);
            color:#fff;
            display:none;
            line-height:1.7;
        `;

        const container =
            button.closest(
                "form, section, .card, .scanner-card, .scan-card"
            );

        if (container) {
            container.appendChild(box);
        } else {
            button.parentElement.appendChild(box);
        }

        return box;
    }

    function show(box, html) {
        box.innerHTML = html;
        box.style.display = "block";
    }

    async function scan(button) {

        const input =
            findURLInput(button);

        const box =
            getResultBox(button);

        if (!input) {
            show(
                box,
                "❌ URL input field nahi mila."
            );
            return;
        }

        let url =
            input.value.trim();

        if (!url) {
            show(
                box,
                "⚠️ Please enter a URL."
            );
            return;
        }

        if (
            !url.startsWith("http://")
            && !url.startsWith("https://")
        ) {
            url = "https://" + url;
        }

        try {
            new URL(url);
        } catch {
            show(
                box,
                "❌ Invalid URL. Example: https://example.com"
            );
            return;
        }

        const oldText =
            button.textContent;

        button.disabled = true;
        button.textContent = "Scanning...";

        show(
            box,
            "🔍 Analysing URL..."
        );

        try {

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
                            url: url
                        })
                    }
                );

            let data;

            try {
                data = await response.json();
            } catch {
                throw new Error(
                    "Server ne valid JSON response nahi diya."
                );
            }

            if (!response.ok) {
                throw new Error(
                    data.error ||
                    `Scan failed (${response.status})`
                );
            }

            const reasons =
                Array.isArray(data.reasons)
                ? data.reasons
                    .map(
                        reason =>
                        `<li>${reason}</li>`
                    )
                    .join("")
                : "";

            show(
                box,
                `
                <div style="font-size:20px;font-weight:800;margin-bottom:10px">
                    ${data.status || "RESULT"}
                </div>

                <div>
                    <strong>URL:</strong>
                    ${data.url || url}
                </div>

                <div>
                    <strong>Risk Score:</strong>
                    ${data.risk_score ?? "—"}%
                </div>

                ${
                    data.ml_prediction
                    ? `
                    <div>
                        <strong>ML Prediction:</strong>
                        ${data.ml_prediction}
                    </div>
                    `
                    : ""
                }

                ${
                    data.ml_probability !== undefined
                    ? `
                    <div>
                        <strong>ML Probability:</strong>
                        ${data.ml_probability}%
                    </div>
                    `
                    : ""
                }

                ${
                    reasons
                    ? `
                    <div style="margin-top:10px">
                        <strong>Analysis:</strong>
                        <ul>${reasons}</ul>
                    </div>
                    `
                    : ""
                }

                ${
                    data.ai_analysis
                    ? (() => {
                        const verdict = (data.status || "SAFE").toUpperCase();
                        const accent = verdict === "PHISHING" ? "#ff6278" : (verdict === "SUSPICIOUS" ? "#ffc552" : "#35e6aa");
                        const softBg = verdict === "PHISHING" ? "rgba(255,98,120,0.14)" : (verdict === "SUSPICIOUS" ? "rgba(255,197,82,0.12)" : "rgba(53,230,170,0.12)");
                        const border = verdict === "PHISHING" ? "rgba(255,98,120,0.38)" : (verdict === "SUSPICIOUS" ? "rgba(255,197,82,0.35)" : "rgba(53,230,170,0.28)");
                        return `
                        <div style="margin-top:14px; padding:16px 18px; border-radius:12px; background:linear-gradient(135deg, rgba(7,31,25,0.96), rgba(4,21,17,0.98)); border:1px solid ${border}; border-left:4px solid ${accent}; box-shadow:0 8px 20px rgba(0,0,0,0.25);">
                            <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px; padding-bottom:10px; border-bottom:1px solid rgba(255,255,255,0.06);">
                                <div style="display:flex; align-items:center; gap:9px; flex-wrap:wrap;">
                                    <span style="width:28px; height:28px; border-radius:8px; display:inline-flex; align-items:center; justify-content:center; background:${softBg}; border:1px solid ${border}; font-size:15px;">🤖</span>
                                    <strong style="color:#edf8f4; font-size:13.5px;">PhishGuard AI Threat Analyst</strong>
                                    <span style="font-size:10px; font-weight:700; letter-spacing:0.5px; text-transform:uppercase; color:${accent}; padding:3px 8px; border-radius:999px; background:${softBg}; border:1px solid ${border};">Explainable AI</span>
                                </div>
                                <span style="font-size:11px; color:#82a49a; padding:3px 9px; border-radius:999px; background:rgba(255,255,255,0.04); border:1px solid rgba(255,255,255,0.08);">${data.ai_analysis.source || "PhishGuard Neural Intelligence (XAI)"}</span>
                            </div>
                            <p style="margin:12px 0 12px 0; font-size:13px; line-height:1.65; color:#cde3db;">${data.ai_analysis.summary || ""}</p>
                            <div style="display:flex; align-items:center; flex-wrap:wrap; gap:8px; padding:9px 12px; border-radius:8px; background:rgba(2,14,11,0.7); border:1px solid rgba(255,255,255,0.06);">
                                <span style="font-size:10px; font-weight:700; letter-spacing:0.6px; text-transform:uppercase; color:#82a49a; padding:2px 6px; border-radius:4px; background:rgba(255,255,255,0.05);">Recommended Action</span>
                                <span style="color:${accent}; font-size:12.5px; font-weight:700;">${data.ai_analysis.action || ""}</span>
                            </div>
                        </div>`;
                    })()
                    : ""
                }
                `
            );

            console.log(
                "PhishGuard scan result:",
                data
            );

        } catch (error) {

            console.error(
                "Scanner error:",
                error
            );

            show(
                box,
                "❌ " + error.message
            );

        } finally {

            button.disabled = false;
            button.textContent = oldText;
        }
    }

    function init() {
        // User dashboard uses its native 5-card scanner + AI Threat Analyst UI.
        if (document.getElementById("dashboardResult")) {
            return;
        }

        const button =
            findScanButton();

        if (!button) {
            return;
        }

        if (
            button.dataset.pgScannerFixed
            === "1"
        ) {
            return;
        }

        button.dataset.pgScannerFixed =
            "1";

        button.addEventListener(
            "click",
            event => {

                event.preventDefault();
                event.stopImmediatePropagation();

                scan(button);

            },
            true
        );

        console.log(
            "✅ PhishGuard Scan URL button connected"
        );
    }

    document.addEventListener(
        "DOMContentLoaded",
        init
    );

    setTimeout(init, 500);
    setTimeout(init, 1500);

})();
