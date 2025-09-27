document.addEventListener('DOMContentLoaded', () => {
    // Dark/Light mode toggle
    const toggleBtn = document.getElementById('darkModeToggle');
    toggleBtn.textContent = document.body.classList.contains('dark-mode') ? 'Light Mode' : 'Dark Mode';
    
    toggleBtn.addEventListener('click', () => {
        document.body.classList.toggle('dark-mode');
        toggleBtn.textContent = document.body.classList.contains('dark-mode') ? 'Light Mode' : 'Dark Mode';
    });

    // Slider Handling
    const sliders = document.querySelectorAll('input[type="range"]');
    const sliderValues = document.querySelectorAll('.slider-value');

    sliders.forEach((slider, index) => {
        sliderValues[index].textContent = slider.value;
        slider.addEventListener('input', () => {
            sliderValues[index].textContent = slider.value;
        });
    });

    // Risk Calculation 
    const calculateBtn = document.getElementById('calculateBtn');
    const resultDiv = document.getElementById('result');
    const riskScoreEl = document.getElementById('risk-score');
    const riskLevelEl = document.getElementById('risk-level');

    calculateBtn.addEventListener('click', () => {
        const getVal = id => parseInt(document.getElementById(id).value);

        // Likelihood sliders
        const skillLevel = getVal('skillLevel');
        const motive = getVal('motive');
        const opportunity = getVal('opportunity');
        const size = getVal('size');
        const easeDiscovery = getVal('easeDiscovery');
        const easeExploit = getVal('easeExploit');
        const awareness = getVal('awareness');
        const intrusionDetection = getVal('intrusionDetection');

        // Impact sliders
        const confidentiality = getVal('confidentiality');
        const integrity = getVal('integrity');
        const availability = getVal('availability');
        const accountability = getVal('accountability');
        const financialDamage = getVal('financialDamage');
        const reputationDamage = getVal('reputationDamage');
        const nonCompliance = getVal('nonCompliance');
        const privacyViolation = getVal('privacyViolation');

        const likelihoodScore = (skillLevel + motive + opportunity + size + easeDiscovery + easeExploit + awareness + intrusionDetection) / 8;
        const impactScore = (confidentiality + integrity + availability + accountability + financialDamage + reputationDamage + nonCompliance + privacyViolation) / 8;

        const getLevel = score => score < 3 ? 'Low' : score < 6 ? 'Medium' : 'High';
        const likelihoodLevel = getLevel(likelihoodScore);
        const impactLevel = getLevel(impactScore);

        let riskLevel = '';
        if (likelihoodLevel === 'Low' && impactLevel === 'Low') riskLevel = 'Note';
        else if (likelihoodLevel === 'Low' && impactLevel === 'Medium') riskLevel = 'Low';
        else if (likelihoodLevel === 'Low' && impactLevel === 'High') riskLevel = 'Medium';
        else if (likelihoodLevel === 'Medium' && impactLevel === 'Low') riskLevel = 'Low';
        else if (likelihoodLevel === 'Medium' && impactLevel === 'Medium') riskLevel = 'Medium';
        else if (likelihoodLevel === 'Medium' && impactLevel === 'High') riskLevel = 'High';
        else if (likelihoodLevel === 'High' && impactLevel === 'Low') riskLevel = 'Medium';
        else if (likelihoodLevel === 'High' && impactLevel === 'Medium') riskLevel = 'High';
        else if (likelihoodLevel === 'High' && impactLevel === 'High') riskLevel = 'Critical';

        let riskClass = riskLevel.toLowerCase();
        if (riskClass === 'note') riskClass = 'low';

        let cvssRange = riskLevel === 'Note' || riskLevel === 'Low' ? '0-3.9' :
                        riskLevel === 'Medium' ? '4-6.9' :
                        riskLevel === 'High' ? '7-8.9' : '9-10';

        riskScoreEl.textContent = `Likelihood: ${likelihoodScore.toFixed(2)} (${likelihoodLevel}), Impact: ${impactScore.toFixed(2)} | Approx. CVSS Range: ${cvssRange}`;
        riskLevelEl.textContent = riskLevel;
        resultDiv.className = `result-box result-${riskClass}`;
        resultDiv.classList.remove('hidden');
    });

    // ----------- CVE Fetch -----------
    window.fetchCVE = async function() {
        const cveId = document.getElementById("cveInput").value.trim();
        const resultDiv = document.getElementById("cveResult");

        if (!cveId) {
            resultDiv.innerHTML = "<p style='color:red;'>Please enter a CVE ID.</p>";
            return;
        }

        try {
            const response = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`);
            if (!response.ok) throw new Error("CVE not found");

            const data = await response.json();
            const cveItem = data.vulnerabilities?.[0]?.cve;

            if (!cveItem) {
                resultDiv.innerHTML = `<p style='color:red;'>CVE not found or rejected.</p>`;
                resultDiv.className = 'result-box';
                return;
            }

            const description = cveItem.descriptions.find(d => d.lang === 'en')?.value || 'No description available';
            const metrics = cveItem.metrics?.cvssMetricV31?.[0] || cveItem.metrics?.cvssMetricV30?.[0];

            let html = `<h4>${cveId}</h4><p><strong>Description:</strong> ${description}</p>`;

            if (metrics) {
                html += `<p><strong>CVSS v3.1 Score:</strong> ${metrics.cvssData.baseScore} (${metrics.cvssData.baseSeverity})</p>`;
                html += `<p><strong>Vector:</strong> ${metrics.cvssData.vectorString}</p>`;
                parseAndSetCVSS(metrics.cvssData.vectorString);
                resultDiv.className = 'result-box result-' + metrics.cvssData.baseSeverity.toLowerCase();
            } else {
                html += `<p>No CVSS v3.1 metrics available.</p>`;
                resultDiv.className = 'result-box';
            }

            resultDiv.innerHTML = html;
        } catch (err) {
            console.error(err);
            resultDiv.innerHTML = `<p style='color:red;'>Error fetching CVE: ${err.message}</p>`;
            resultDiv.className = 'result-box';
        }
    };

    // CVSS Vector Parser 
    function parseAndSetCVSS(vector) {
        const parts = vector.split('/');
        parts.forEach(part => {
            const [key, value] = part.split(':');
            if (key && value) {
                const select = document.getElementById(key.toLowerCase());
                if (select) select.value = value;
            }
        });
    }

    // CVSS Calculation 
    window.calculateCVSS = function() {
        const av = document.getElementById("av").value;
        const ac = document.getElementById("ac").value;
        const pr = document.getElementById("pr").value;
        const ui = document.getElementById("ui").value;
        const s = document.getElementById("s").value;
        const c = document.getElementById("c").value;
        const i = document.getElementById("i").value;
        const a = document.getElementById("a").value;

        const metrics = {
            AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
            AC: { L: 0.77, H: 0.44 },
            PR: {
                U: { N: 0.85, L: 0.62, H: 0.27 },
                C: { N: 0.85, L: 0.68, H: 0.5 }
            },
            UI: { N: 0.85, R: 0.62 },
            C: { N: 0.0, L: 0.22, H: 0.56 },
            I: { N: 0.0, L: 0.22, H: 0.56 },
            A: { N: 0.0, L: 0.22, H: 0.56 }
        };

        const exploitability = 8.22 * metrics.AV[av] * metrics.AC[ac] * metrics.PR[s][pr] * metrics.UI[ui];
        const impactSub = 1 - ((1 - metrics.C[c]) * (1 - metrics.I[i]) * (1 - metrics.A[a]));
        let impact = s === "U" ? 6.42 * impactSub : 7.52 * (impactSub - 0.029) - 3.25 * Math.pow((impactSub - 0.02), 15);

        let baseScore = impact <= 0 ? 0 : s === "U" ? Math.min(impact + exploitability, 10).toFixed(1) : Math.min(1.08 * (impact + exploitability), 10).toFixed(1);

        let severity = baseScore <= 3.9 ? "Low" : baseScore <= 6.9 ? "Medium" : baseScore <= 8.9 ? "High" : "Critical";

        const cvssResultDiv = document.getElementById("cvssResult");
        cvssResultDiv.innerHTML = `
            <p>CVSS Base Score: <strong>${baseScore}</strong> (${severity})</p>
            <p>Vector: CVSS:3.1/AV:${av}/AC:${ac}/PR:${pr}/UI:${ui}/S:${s}/C:${c}/I:${i}/A:${a}</p>
        `;
        cvssResultDiv.className = 'result-box result-' + severity.toLowerCase();
    };
});
