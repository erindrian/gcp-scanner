# GCP CIS Scanner

This project is a scanner for GCP CIS compliance. It audits GCP environments against CIS Benchmark v3.0 controls for Cloud Storage and IAM.

## Installation

To install the GCP CIS Scanner, clone the repository and install the required dependencies:

```bash
git clone https://github.com/yourusername/gcp-cis-scanner.git
cd gcp-cis-scanner
pip install -r requirements.txt
```

## Usage

To run the scanner, use the following command:

```bash
gcp-cis-scan
```

You can specify additional options as needed.

## Dependencies

The following libraries are required to run the GCP CIS Scanner:

- google-cloud-storage
- google-cloud-iam
- google-cloud-resource-manager
- python-dotenv

Make sure to install these dependencies using the `requirements.txt` file.
