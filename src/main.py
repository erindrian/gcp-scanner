import argparse
from modules.bucket_scanner import BucketScanner
from modules.iam_scanner import IAMScanner

def main(project_id):
    bucket_scanner = BucketScanner(project_id)
    iam_scanner = IAMScanner(project_id)

    print("\n--- Starting GCP CIS 3.0 Compliance Scan ---\n")

    # Scan Buckets
    bucket_findings = bucket_scanner.scan_buckets()
    for finding in bucket_findings:
        print(f"[{finding['check_id']}] {finding['resource']} - {finding['status']}")
        print(f"Message: {finding['message']}\n")

    # Scan IAM
    iam_findings = iam_scanner.scan_iam()
    for finding in iam_findings:
        print(f"[{finding['check_id']}] {finding['resource']} - {finding['status']}")
        print(f"Message: {finding['message']}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GCP CIS 3.0 Compliance Scanner")
    parser.add_argument('--project', required=True, help='GCP Project ID')
    args = parser.parse_args()

    main(args.project)
    