from google.cloud import iam  # Importing IAM module
from google.cloud import resourcemanager_v3
from google.api_core.exceptions import GoogleAPICallError

class IAMScanner:
    def __init__(self, project_id):
        self.project_id = project_id
        self.iam_client = iam.IAMClient()  # Using IAMClient from iam
        self.resource_client = resourcemanager_v3.ProjectsClient()

    def check_corporate_logins(self, policy):
        """CIS 1.1: Ensure corporate login credentials are used"""
        non_corporate_users = [member for member in policy.bindings if "user:" in member]
        if non_corporate_users:
            return False, "Non-corporate users found"
        return True, "All users are corporate"

    def check_service_account_keys(self, service_account):
        """CIS 1.4: Ensure service account keys are managed properly"""
        keys = self.iam_client.list_service_account_keys(service_account.name)
        if len(keys) > 0:
            return False, "User-managed keys found"
        return True, "No user-managed keys found"

    def scan_iam(self):
        findings = []
        try:
            project = self.resource_client.get_project(name=f"projects/{self.project_id}")
            policy = self.iam_client.get_iam_policy(resource=project.name)

            # CIS 1.1 Check
            compliant, msg = self.check_corporate_logins(policy)
            findings.append({
                "check_id": "CIS 1.1",
                "status": "PASS" if compliant else "FAIL",
                "resource": f"Project: {self.project_id}",
                "message": msg
            })

            # CIS 1.4 Check
            service_accounts = self.iam_client.list_service_accounts(parent=project.name)
            for service_account in service_accounts:
                compliant, msg = self.check_service_account_keys(service_account)
                findings.append({
                    "check_id": "CIS 1.4",
                    "status": "PASS" if compliant else "FAIL",
                    "resource": service_account.email,
                    "message": msg
                })
        except GoogleAPICallError as e:
            print(f"IAM scan error: {e}")
        return findings
