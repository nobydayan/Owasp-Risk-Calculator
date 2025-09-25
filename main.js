document.addEventListener('DOMContentLoaded', () => {

    // Select all sliders and their corresponding value displays
    const sliders = document.querySelectorAll('input[type="range"]');
    const sliderValues = document.querySelectorAll('.slider-value');

    // Function to update the displayed value next to the slider
    const updateSliderValue = (slider, valueDisplay) => {
        valueDisplay.textContent = slider.value;
    };

    // Add event listeners to all sliders to update the display on input
    sliders.forEach((slider, index) => {
        // Initialize display
        updateSliderValue(slider, sliderValues[index]);
        
        // Add listener for changes
        slider.addEventListener('input', () => {
            updateSliderValue(slider, sliderValues[index]);
        });
    });

    // Select the button and result elements
    const calculateBtn = document.getElementById('calculateBtn');
    const resultDiv = document.getElementById('result');
    const riskScoreEl = document.getElementById('risk-score');
    const riskLevelEl = document.getElementById('risk-level');

    // Add click event listener to the calculate button
    calculateBtn.addEventListener('click', () => {
        // Get values from all sliders and convert them to numbers
        const skillLevel = parseInt(document.getElementById('skillLevel').value);
        const motive = parseInt(document.getElementById('motive').value);
        const opportunity = parseInt(document.getElementById('opportunity').value);
        const size = parseInt(document.getElementById('size').value);
        const easeDiscovery = parseInt(document.getElementById('easeDiscovery').value);
        const easeExploit = parseInt(document.getElementById('easeExploit').value);
        const awareness = parseInt(document.getElementById('awareness').value);
        const intrusionDetection = parseInt(document.getElementById('intrusionDetection').value);

        const confidentiality = parseInt(document.getElementById('confidentiality').value);
        const integrity = parseInt(document.getElementById('integrity').value);
        const availability = parseInt(document.getElementById('availability').value);
        const accountability = parseInt(document.getElementById('accountability').value);
        const financialDamage = parseInt(document.getElementById('financialDamage').value);
        const reputationDamage = parseInt(document.getElementById('reputationDamage').value);
        const nonCompliance = parseInt(document.getElementById('nonCompliance').value);
        const privacyViolation = parseInt(document.getElementById('privacyViolation').value);

        // --- CALCULATION LOGIC ---
        const likelihoodScore = (skillLevel + motive + opportunity + size + easeDiscovery + easeExploit + awareness + intrusionDetection) / 8;
        const impactScore = (confidentiality + integrity + availability + accountability + financialDamage + reputationDamage + nonCompliance + privacyViolation) / 8;

        // Determine levels
        const getLevel = (score) => {
            if (score < 3) return 'Low';
            if (score < 6) return 'Medium';
            return 'High';
        };

        const likelihoodLevel = getLevel(likelihoodScore);
        const impactLevel = getLevel(impactScore);

        // Determine overall risk level using OWASP matrix
        let riskLevel = '';
        if (likelihoodLevel === 'Low' && impactLevel === 'Low') riskLevel = 'Note'; // or Low
        else if (likelihoodLevel === 'Low' && impactLevel === 'Medium') riskLevel = 'Low';
        else if (likelihoodLevel === 'Low' && impactLevel === 'High') riskLevel = 'Medium';
        else if (likelihoodLevel === 'Medium' && impactLevel === 'Low') riskLevel = 'Low';
        else if (likelihoodLevel === 'Medium' && impactLevel === 'Medium') riskLevel = 'Medium';
        else if (likelihoodLevel === 'Medium' && impactLevel === 'High') riskLevel = 'High';
        else if (likelihoodLevel === 'High' && impactLevel === 'Low') riskLevel = 'Medium';
        else if (likelihoodLevel === 'High' && impactLevel === 'Medium') riskLevel = 'High';
        else if (likelihoodLevel === 'High' && impactLevel === 'High') riskLevel = 'Critical';

        // Map to class
        let riskClass = riskLevel.toLowerCase();
        if (riskClass === 'note') riskClass = 'low'; // treat note as low

        // --- DISPLAY RESULTS ---
        // Update the score and level text
        riskScoreEl.textContent = `Likelihood: ${likelihoodScore.toFixed(2)} (${likelihoodLevel}), Impact: ${impactScore.toFixed(2)} (${impactLevel})`;

        // Map OWASP to approximate CVSS range
        let cvssRange = '';
        if (riskLevel === 'Note' || riskLevel === 'Low') cvssRange = '0-3.9';
        else if (riskLevel === 'Medium') cvssRange = '4-6.9';
        else if (riskLevel === 'High') cvssRange = '7-8.9';
        else if (riskLevel === 'Critical') cvssRange = '9-10';

        riskScoreEl.textContent += ` | Approx. CVSS Range: ${cvssRange}`;

        riskLevelEl.textContent = riskLevel;

        // Update the color-coded class for the result box
        resultDiv.className = 'result-box result-' + riskClass;

        // Make the result box visible
        resultDiv.classList.remove('hidden');
    });

    // CVE Fetch Function
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
            const cveItem = data.vulnerabilities[0].cve;
            const description = cveItem.descriptions.find(d => d.lang === 'en')?.value || 'No description available';
            const metrics = cveItem.metrics?.cvssMetricV31?.[0] || cveItem.metrics?.cvssMetricV30?.[0];

            let html = `<h4>${cveId}</h4>`;
            html += `<p><strong>Description:</strong> ${description}</p>`;

            if (metrics) {
                html += `<p><strong>CVSS v3.1 Score:</strong> ${metrics.cvssData.baseScore} (${metrics.cvssData.baseSeverity})</p>`;
                html += `<p><strong>Vector:</strong> ${metrics.cvssData.vectorString}</p>`;

                // Auto-fill CVSS calculator
                const vector = metrics.cvssData.vectorString;
                parseAndSetCVSS(vector);
            } else {
                html += `<p>No CVSS v3.1 metrics available.</p>`;
            }

            resultDiv.innerHTML = html;
            if (metrics) {
                resultDiv.className = 'result-box result-' + metrics.cvssData.baseSeverity.toLowerCase();
            } else {
                resultDiv.className = 'result-box';
            }

        } catch (err) {
            console.error(err);
            resultDiv.innerHTML = `<p style='color:red;'>Error fetching CVE: ${err.message}</p>`;
            resultDiv.className = 'result-box';
        }
    };

    // Function to parse CVSS vector and set selects
    function parseAndSetCVSS(vector) {
        const parts = vector.split('/');
        parts.forEach(part => {
            const [key, value] = part.split(':');
            if (key && value) {
                const select = document.getElementById(key.toLowerCase());
                if (select) {
                    select.value = value;
                }
            }
        });
    }

    // CVSS Calculation Function
    window.calculateCVSS = function() {
        // Collect values
        const av = document.getElementById("av").value;
        const ac = document.getElementById("ac").value;
        const pr = document.getElementById("pr").value;
        const ui = document.getElementById("ui").value;
        const s = document.getElementById("s").value;
        const c = document.getElementById("c").value;
        const i = document.getElementById("i").value;
        const a = document.getElementById("a").value;

        // Metric weights (from CVSS v3.1 spec)
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

        // Exploitability sub-score
        const exploitability = 8.22 *
            metrics.AV[av] *
            metrics.AC[ac] *
            metrics.PR[s][pr] *
            metrics.UI[ui];

        // Impact sub-score
        const impactSub = 1 - ((1 - metrics.C[c]) * (1 - metrics.I[i]) * (1 - metrics.A[a]));
        let impact = (s === "U") ? 6.42 * impactSub : 7.52 * (impactSub - 0.029) - 3.25 * Math.pow((impactSub - 0.02), 15);

        // Final score
        let baseScore;
        if (impact <= 0) {
            baseScore = 0;
        } else {
            if (s === "U") {
                baseScore = Math.min((impact + exploitability), 10).toFixed(1);
            } else {
                baseScore = Math.min(1.08 * (impact + exploitability), 10).toFixed(1);
            }
        }

        // Severity rating
        let severity = "None";
        if (baseScore >= 0.1 && baseScore <= 3.9) severity = "Low";
        else if (baseScore <= 6.9) severity = "Medium";
        else if (baseScore <= 8.9) severity = "High";
        else if (baseScore >= 9.0) severity = "Critical";

        // Output
        const cvssResultDiv = document.getElementById("cvssResult");
        cvssResultDiv.innerHTML = `
            <p>CVSS Base Score: <strong>${baseScore}</strong> (${severity})</p>
            <p>Vector: CVSS:3.1/AV:${av}/AC:${ac}/PR:${pr}/UI:${ui}/S:${s}/C:${c}/I:${i}/A:${a}</p>
        `;
        cvssResultDiv.className = 'result-box result-' + severity.toLowerCase();
    };
});
