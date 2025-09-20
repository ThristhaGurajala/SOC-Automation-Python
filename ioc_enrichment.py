"""
IOC Enrichment Script
Author: Thristha Gurajala
Description:
Reads indicators from indicators.txt, simulates API enrichment,
and saves results to results.json for SOC automation workflows.
"""

import json

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
        print(f"[+] {result['indicator']} → {result['status']}")

    # Save results to JSON file
    with open(output_file, "w") as f:
        json.dump(results, f, indent=4)

    print(f"\nIOC enrichment completed. Results saved to {output_file}")

if __name__ == "__main__":
    main()
