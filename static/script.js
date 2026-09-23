async function scanURL() {

    const urlInput = document.getElementById("urlInput");
    const loading = document.getElementById("loading");
    const resultCard = document.getElementById("resultCard");

    const statusText = document.getElementById("statusText");
    const riskScore = document.getElementById("riskScore");
    const scannedUrl = document.getElementById("scannedUrl");
    const reasonList = document.getElementById("reasonList");

    const url = urlInput.value.trim();

    if (!url) {
        alert("Please enter a URL.");
        return;
    }

    loading.classList.remove("hidden");
    resultCard.classList.add("hidden");

    try {

        const response = await fetch("/api/scan", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                url: url
            })
        });

        const data = await response.json();

        loading.classList.add("hidden");

        if (!response.ok) {
            alert(data.error || "Something went wrong.");
            return;
        }

        statusText.textContent = data.status;
        riskScore.textContent = data.risk_score;
        scannedUrl.textContent = data.url;

        const ruleStatus = document.getElementById("ruleStatus");
        const mlPrediction = document.getElementById("mlPrediction");
        const mlProbability = document.getElementById("mlProbability");

        ruleStatus.textContent = data.rule_status;
        mlPrediction.textContent = data.ml_prediction;
        mlProbability.textContent = data.ml_probability;

        ruleStatus.className = "";
        mlPrediction.className = "";

        if (data.rule_status === "SAFE") {
            ruleStatus.classList.add("safe");
        } else if (data.rule_status === "SUSPICIOUS") {
            ruleStatus.classList.add("suspicious");
        } else {
            ruleStatus.classList.add("phishing");
        }

        if (data.ml_prediction === "SAFE") {
            mlPrediction.classList.add("safe");
        } else {
            mlPrediction.classList.add("phishing");
        }

        statusText.className = "";

        if (data.status === "SAFE") {
            statusText.classList.add("safe");
        }

        else if (data.status === "SUSPICIOUS") {
            statusText.classList.add("suspicious");
        }

        else if (data.status === "PHISHING") {
            statusText.classList.add("phishing");
        }

        reasonList.innerHTML = "";

        if (data.reasons.length === 0) {

            const li = document.createElement("li");
            li.textContent = "No major suspicious URL patterns detected.";
            reasonList.appendChild(li);

        } else {

            data.reasons.forEach(function(reason) {

                const li = document.createElement("li");
                li.textContent = reason;
                reasonList.appendChild(li);

            });
        }

        resultCard.classList.remove("hidden");

        loadHistory();
        loadStats();
        loadScanChart();

    }

    catch (error) {

        loading.classList.add("hidden");
        alert("Unable to connect to the PhishGuard server.");

        console.error(error);
    }
}

async function loadHistory() {
    const historyTable = document.getElementById("historyTable");

    if (!historyTable) {
        return;
    }

    try {
        const response = await fetch("/api/history");
        const history = await response.json();

        historyTable.innerHTML = "";

        history.forEach(function(scan) {
            const row = document.createElement("tr");

            const urlCell = document.createElement("td");
            urlCell.textContent = scan.url;

            const statusCell = document.createElement("td");
            statusCell.textContent = scan.status || "—";
            if (scan.status) {
                statusCell.classList.add(scan.status.toLowerCase());
            }

            const ruleCell = document.createElement("td");
            ruleCell.textContent = scan.rule_status || "—";
            if (scan.rule_status) {
                ruleCell.classList.add(scan.rule_status.toLowerCase());
            }

            const mlCell = document.createElement("td");
            mlCell.textContent = scan.ml_prediction || "—";
            if (scan.ml_prediction) {
                mlCell.classList.add(scan.ml_prediction.toLowerCase());
            }

            const mlProbabilityCell = document.createElement("td");
            mlProbabilityCell.textContent =
                scan.ml_probability != null
                    ? scan.ml_probability + "%"
                    : "—";

            const riskCell = document.createElement("td");
            riskCell.textContent = scan.risk_score + "%";

            const timeCell = document.createElement("td");
            timeCell.textContent = scan.scanned_at;

            row.appendChild(urlCell);
            row.appendChild(statusCell);
            row.appendChild(ruleCell);
            row.appendChild(mlCell);
            row.appendChild(mlProbabilityCell);
            row.appendChild(riskCell);
            row.appendChild(timeCell);

            historyTable.appendChild(row);
        });

    } catch (error) {
        console.error("Unable to load scan history:", error);
    }
}

document.addEventListener("DOMContentLoaded", loadHistory);

async function loadStats() {
    try {
        const response = await fetch("/api/stats");
        const stats = await response.json();

        document.getElementById("totalScans").textContent = stats.total;
        document.getElementById("safeScans").textContent = stats.safe;
        document.getElementById("suspiciousScans").textContent = stats.suspicious;
        document.getElementById("phishingScans").textContent = stats.phishing;

    } catch (error) {
        console.error("Unable to load stats:", error);
    }
}

document.addEventListener("DOMContentLoaded", loadStats);

let scanChartInstance = null;

async function loadScanChart() {
    try {
        const response = await fetch("/api/stats");
        const stats = await response.json();

        const canvas = document.getElementById("scanChart");

        if (!canvas || typeof Chart === "undefined") {
            return;
        }

        if (scanChartInstance) {
            scanChartInstance.destroy();
        }

        scanChartInstance = new Chart(canvas, {
            type: "doughnut",

            data: {
                labels: [
                    "Safe",
                    "Suspicious",
                    "Phishing"
                ],

                datasets: [{
                    data: [
                        stats.safe,
                        stats.suspicious,
                        stats.phishing
                    ]
                }]
            },

            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: "bottom"
                    }
                }
            }
        });

    } catch (error) {
        console.error("Unable to load chart:", error);
    }
}

document.addEventListener(
    "DOMContentLoaded",
    loadScanChart
);

