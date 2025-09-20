"""
IOC Enrichment Script
Author: Thristha Gurajala
Description:
Reads indicators from indicators.txt, simulates IOC enrichment,
and demonstrates secure API key handling using dotenv.
"""

import json
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY", "not_set")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "not_set")

def mock_query_api(indicator):
    """
    Mock function that simulates querying an API.
    In real use, this would call VirusTotal or AbuseIPDB with an API key.
    """
    if "malicious" in indicator:
        return {
            "indicator": indicator,
            "status": "malicious",
            "source": "VirusTotal",
            "api_key_used": VT_API_KEY[:6] + "..." if VT_API_KEY != "not_set" else "missing"
        }
    else:
        return {
            "indicator": indicator,
            "status": "clean",
            "source": "AbuseIPDB",
            "api_key_used": ABUSEIPDB_API_KEY[:6] + "..." if ABUSEIPDB_API_KEY != "not_set" else "missing"
        }

def main():
    input_file = "indicators.txt"
    output_file = "results.json"
    results = []

    print("Starting IOC enrichment...\n")

    # Read indicators from file
    try:
        with open(input_file, "r") as f:
            indicators = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: {input_file} not found. Please create the file with IOCs.")
        return

    # Process indicators
    for ioc in indicators:
        result = mock_query_api(ioc)
        results.append(result)
        print(f"[+] {result['indicator']} → {result['status']} (source: {result['source']})")

    # Save results to JSON file
    with open(output_file, "w") as f:
        json.dump(results, f, indent=4)

    print(f"\nIOC enrichment completed. Results saved to {output_file}")

if __name__ == "__main__":
    main()

