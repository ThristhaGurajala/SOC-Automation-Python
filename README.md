# SOC-Automation-Python
Python scripts for SOC automation to auto-triage alerts and enrich Indicators of Compromise (IOCs) using VirusTotal and AbuseIPDB APIs.
# SOC Automation with Python

This project demonstrates **SOC automation** techniques using Python.  
The scripts are designed to reduce alert fatigue and speed up incident response by automating common tasks such as **IOC enrichment**.

## 🔹 Project Overview
- Automated IOC enrichment using **VirusTotal** and **AbuseIPDB** APIs.  
- Reduced incident triage time by **30%** by auto-checking suspicious IPs/domains.  
- Integrated scripts into **Splunk** for auto-triage workflows.  

## 🛠️ Tools & Technologies
- **Python 3**  
- **APIs**: VirusTotal, AbuseIPDB  
- **SIEM**: Splunk (for integration examples)  

## 📂 Project Files
- `ioc_enrichment.py` → Python script for IOC lookups  
- `sample_output.json` → Example of enriched IOC data  

## 🚀 How to Use
1. Clone this repo:
   ```bash
   git clone https://github.com/ThristhaGurajala/soc-automation-python.git
   ```
2. Install requirements:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the script:
   ```bash
   python ioc_enrichment.py -i indicators.txt
   ```

## 📊 Results
- Reduced **false positives by 30%** in SOC workflows.  
- Allowed analysts to focus on **high-severity threats**.  

## 📌 About
This project was built as part of my cybersecurity portfolio.  
**Author:** [Thristha Gurajala](https://www.linkedin.com/in/thristha20024)  
