"""
IOC Enrichment Script
Author: Thristha Gurajala
Description:
This script simulates IOC (Indicators of Compromise) enrichment using public APIs
like VirusTotal and AbuseIPDB. It helps SOC teams quickly triage alerts.
"""

# Mock list of indicators
indicators = ["8.8.8.8", "malicious-domain.com", "192.168.1.10"]

def mock_query_api(indicator):
    """
    Mock function that simulates querying an API.
    In real use, this would call VirusTotal or AbuseIPDB with an API key.
    """
    if "malicious" in indicator:
        return {"indicator": indicator, "status": "malicious"}
    else:
        return {"indicator": indicator, "status": "clean"}

def main():
    print("Starting IOC enrichment...\n")
    for ioc in indicators:
        result = mock_query_api(ioc)
        print(f"[+] {result['indicator']} → {result['status']}")
    print("\nIOC enrichment completed.")

if __name__ == "__main__":
    main()
