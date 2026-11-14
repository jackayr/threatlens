import requests
import argparse
import sys
import csv

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_vulnerabilities():
    try:
        response = requests.get(URL, timeout=15)
        response.raise_for_status()
        data = response.json()
        return data["vulnerabilities"]
    except requests.exceptions.RequestException as error:
        print(f"Failed to fetch vulnerabilities: {error}", file=sys.stderr) 
        sys.exit(1)


def filter_by_vendor(vulnerabilities, vendor):
    results = []
    vendor = vendor.lower()
    for vulnerability in vulnerabilities:
        if vulnerability.get("vendorProject", "").lower() == vendor:
            results.append(vulnerability)

    return results

def export_to_csv(vulnerabilities, filename):
    fields = [
        "cveID", 
        "vendorProject",
        "product",
        "vulnerabilityName",
        "dateAdded",
        "knownRansomwareCampaignUse"
    ]

    try:
        with open(filename, "w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(
                file,
                fieldnames = fields,
                extrasaction="ignore"
            )
            writer.writeheader()
            writer.writerows(vulnerabilities)
    except OSError as error:
        print(f"Failed to export CSV: {error}", file=sys.stderr)
        sys.exit(1)



if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description="ThreatLens - CISA KEV vulnerability filtering tool"
    )
    parser.add_argument("--vendor", type=str, required=True)
    parser.add_argument("--limit", type=int, default=5)
    parser.add_argument("--output", type=str)

    args = parser.parse_args()

    vendor = args.vendor.strip()
    limit = args.limit
    outputfile = args.output

    # Validating user input
    if args.limit < 0:
        parser.error("--limit must be zero or greater.")
    elif args.vendor.strip() == "":
        parser.error("--vendor must not be empty.")
    
    if args.output is not None and not args.output.strip():
            parser.error("--output must not be empty.")


    
    
    vulnerabilities = fetch_vulnerabilities()
    
    print(f"Total vulnerabilities: {len(vulnerabilities)}")

    vendorinfo = filter_by_vendor(vulnerabilities, vendor)

    print(f"{vendor} vulnerabilities:  {len(vendorinfo)}")
    for vuln in vendorinfo[:limit]:
        print(vuln["cveID"], "-", vuln["vendorProject"])

    if args.output is not None:
        export_to_csv(vendorinfo,outputfile)
        print(f"Exported {len(vendorinfo)} records to {args.output}")


    