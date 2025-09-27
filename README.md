🛡️ OWASP & CVSS Risk Calculator

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)
![Contributions](https://img.shields.io/badge/contributions-welcome-brightgreen.svg)

Owasp Risk Calcultor is build based on Owasp Risk Rating Methodology

I've been working on refining the specific input factors for the project. The goal is to design a risk rating calculator that allows a user to identify a risk level for a particular area of their system/organzation . I'm focusing on defining a simplified input model based on a Likelihood Score and an Impact Score. The UI design will be simple, with sliders and color-coded risk levels. The output will be clear and actionable.

By following the approach here, it is possible to estimate the severity of all of these risks to the business and make an informed decision about what to do about those risks. Having a system in place for rating risks will save time and eliminate arguing about priorities. This system will help to ensure that the business doesn’t get distracted by minor risks while ignoring more serious risks that are less well understood.

In the sections below, the factors that make up “likelihood” and “impact” for application security are broken down. The tester is shown how to combine them to determine the overall severity for the risk.

  Step 1: Identifying a Risk
  Step 2: Factors for Estimating Likelihood
  Step 3: Factors for Estimating Impact
  Step 4: Determining Severity of the Risk
  Step 5: Deciding What to Fix
  Step 6: Customizing Your Risk Rating Model

Features
1. OWASP Risk Rating Calculator (Likelihood + Impact, 16 factors)
2. CVSS v3.1 Calculator (Base Score, Vector, Severity)
3. CVE Lookup (via NVD API v2.0) with auto-populated CVSS data
4. Color-coded results (Low, Medium, High, Critical)
5. Clean UI with sliders, dropdowns, and sections

Prerequisites
- Modern browser (Chrome, Firefox, Edge, etc.)
- Internet connection (for CVE lookup API)

Run Locally
```bash
git clone https://github.com/YOURUSERNAME/vuln-risk-calculator.git
cd vuln-risk-calculator
open index.html



Contributions are welcome!  
Open an issue for bugs or feature requests
Fork the repo and submit a pull request
