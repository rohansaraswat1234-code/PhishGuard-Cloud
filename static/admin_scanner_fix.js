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
                    ? `
                    <div style="margin-top:12px; padding:12px; border-radius:8px; background:rgba(99,102,241,0.18); border:1px solid rgba(99,102,241,0.4);">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:5px;">
                            <strong style="color:#a5b4fc; font-size:13px;">🤖 PhishGuard AI Threat Analyst</strong>
                            <span style="font-size:10px; color:#94a3b8; padding:2px 6px; border-radius:10px; background:rgba(99,102,241,0.25);">${data.ai_analysis.source || "Explainable AI"}</span>
                        </div>
                        <p style="margin:0 0 6px 0; font-size:12.5px; line-height:1.5; color:#e2e8f0;">${data.ai_analysis.summary || ""}</p>
                        <div style="font-size:11.5px; border-top:1px solid rgba(255,255,255,0.08); padding-top:5px;">
                            <strong style="color:#94a3b8;">ACTION:</strong>
                            <span style="color:#38bdf8; font-weight:600;"> ${data.ai_analysis.action || ""}</span>
                        </div>
                    </div>
                    `
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
