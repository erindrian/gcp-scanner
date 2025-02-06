from google.cloud import storage
from google.api_core.exceptions import GoogleAPICallError

class BucketScanner:
    def __init__(self, project_id):
        self.project_id = project_id
        self.storage_client = storage.Client(project=project_id)

    def check_bucket_public_access(self, bucket):
        """CIS 5.1: Ensure Cloud Storage buckets are not publicly accessible"""
        policy = bucket.get_iam_policy(requested_policy_version=3)
        public_members = {"allUsers", "allAuthenticatedUsers"}
        
        for binding in policy.bindings:
            if public_members.intersection(binding["members"]):
                return False, f"Public access granted via {binding['role']}"
        return True, "No public access detected"

    def check_uniform_bucket_level_access(self, bucket):
        """CIS 5.2: Ensure uniform bucket-level access is enabled"""
        if bucket.iam_configuration.uniform_bucket_level_access_enabled:
            return True, "Uniform bucket-level access enabled"
        return False, "Uniform bucket-level access disabled"

    def scan_buckets(self):
        findings = []
        try:
            for bucket in self.storage_client.list_buckets():
                # CIS 5.1 Check
                compliant, msg = self.check_bucket_public_access(bucket)
                findings.append({
                    "check_id": "CIS 5.1",
                    "status": "PASS" if compliant else "FAIL",
                    "resource": f"gs://{bucket.name}",
                    "message": msg
                })
                
                # CIS 5.2 Check
                compliant, msg = self.check_uniform_bucket_level_access(bucket)
                findings.append({
                    "check_id": "CIS 5.2",
                    "status": "PASS" if compliant else "FAIL",
                    "resource": f"gs://{bucket.name}",
                    "message": msg
                })
        except GoogleAPICallError as e:
            print(f"Bucket scan error: {e}")
        return findings