#!/usr/bin/env python3
"""
AWS S3 Security Checker - Educational Tool
Checks S3 bucket permissions and configurations
"""

import boto3 # type: ignore
import json
from botocore.exceptions import ClientError # type: ignore

class S3SecurityChecker:
    def __init__(self, profile_name=None):
        """Initialize S3 client"""
        if profile_name:
            self.session = boto3.Session(profile_name=profile_name)
        else:
            self.session = boto3.Session()
        
        self.s3 = self.session.client('s3')
        self.issues = []
        
    def list_buckets(self):
        """List all S3 buckets"""
        try:
            response = self.s3.list_buckets()
            return [bucket['Name'] for bucket in response['Buckets']]
        except ClientError as e:
            print(f"❌ Error listing buckets: {e}")
            return []
    
    def check_bucket_public_access(self, bucket_name):
        """Check if bucket has public access"""
        try:
            # Check bucket ACL
            acl = self.s3.get_bucket_acl(Bucket=bucket_name)
            for grant in acl['Grants']:
                grantee = grant.get('Grantee', {})
                if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                    self.issues.append({
                        'bucket': bucket_name,
                        'issue': 'Public read access via ACL',
                        'severity': 'HIGH',
                        'fix': 'Remove public ACL grants'
                    })
            
            # Check bucket policy
            try:
                policy = self.s3.get_bucket_policy(Bucket=bucket_name)
                policy_json = json.loads(policy['Policy'])
                if self._check_public_policy(policy_json):
                    self.issues.append({
                        'bucket': bucket_name,
                        'issue': 'Public access via bucket policy',
                        'severity': 'HIGH',
                        'fix': 'Restrict bucket policy to specific principals'
                    })
            except ClientError:
                pass  # No policy exists
            
            # Check Block Public Access settings
            try:
                block = self.s3.get_public_access_block(Bucket=bucket_name)
                settings = block['PublicAccessBlockConfiguration']
                
                if not settings.get('BlockPublicAcls', False):
                    self.issues.append({
                        'bucket': bucket_name,
                        'issue': 'BlockPublicAcls is disabled',
                        'severity': 'MEDIUM',
                        'fix': 'Enable BlockPublicAcls'
                    })
                if not settings.get('BlockPublicPolicy', False):
                    self.issues.append({
                        'bucket': bucket_name,
                        'issue': 'BlockPublicPolicy is disabled',
                        'severity': 'MEDIUM',
                        'fix': 'Enable BlockPublicPolicy'
                    })
            except ClientError:
                self.issues.append({
                    'bucket': bucket_name,
                    'issue': 'Public Access Block not configured',
                    'severity': 'MEDIUM',
                    'fix': 'Configure Public Access Block settings'
                })
                
        except ClientError as e:
            print(f"❌ Error checking bucket {bucket_name}: {e}")
    
    def _check_public_policy(self, policy):
        """Check if policy allows public access"""
        for statement in policy.get('Statement', []):
            principal = statement.get('Principal', {})
            if principal == '*' or principal.get('AWS') == '*':
                return True
        return False
    
    def check_bucket_encryption(self, bucket_name):
        """Check if bucket encryption is enabled"""
        try:
            self.s3.get_bucket_encryption(Bucket=bucket_name)
        except ClientError:
            self.issues.append({
                'bucket': bucket_name,
                'issue': 'Default encryption not enabled',
                'severity': 'MEDIUM',
                'fix': 'Enable default encryption (AES-256 or KMS)'
            })
    
    def check_bucket_versioning(self, bucket_name):
        """Check if bucket versioning is enabled"""
        try:
            versioning = self.s3.get_bucket_versioning(Bucket=bucket_name)
            if versioning.get('Status') != 'Enabled':
                self.issues.append({
                    'bucket': bucket_name,
                    'issue': 'Bucket versioning not enabled',
                    'severity': 'LOW',
                    'fix': 'Enable versioning for data protection'
                })
        except ClientError:
            pass
    
    def check_bucket_logging(self, bucket_name):
        """Check if access logging is enabled"""
        try:
            logging = self.s3.get_bucket_logging(Bucket=bucket_name)
            if 'LoggingEnabled' not in logging:
                self.issues.append({
                    'bucket': bucket_name,
                    'issue': 'Access logging not enabled',
                    'severity': 'LOW',
                    'fix': 'Enable server access logging'
                })
        except ClientError:
            pass
    
    def run_full_audit(self):
        """Run complete S3 security audit"""
        print("\n" + "="*60)
        print("🔒 AWS S3 SECURITY AUDIT")
        print("="*60)
        
        buckets = self.list_buckets()
        if not buckets:
            print("❌ No buckets found or unable to list buckets")
            return
        
        print(f"\n📦 Found {len(buckets)} buckets to audit\n")
        
        for bucket in buckets:
            print(f"\n[*] Auditing bucket: {bucket}")
            self.check_bucket_public_access(bucket)
            self.check_bucket_encryption(bucket)
            self.check_bucket_versioning(bucket)
            self.check_bucket_logging(bucket)
        
        self.generate_report()
    
    def generate_report(self):
        """Generate security audit report"""
        print("\n" + "="*60)
        print("📊 S3 SECURITY AUDIT REPORT")
        print("="*60)
        
        if not self.issues:
            print("\n✅ No security issues found!")
            return
        
        # Group by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        self.issues.sort(key=lambda x: severity_order.get(x['severity'], 4))
        
        print(f"\n⚠️ Found {len(self.issues)} security issues:\n")
        
        for i, issue in enumerate(self.issues, 1):
            print(f"{i}. [{issue['severity']}] {issue['bucket']}")
            print(f"   Issue: {issue['issue']}")
            print(f"   Fix: {issue['fix']}")
            print()

def main():
    print("="*60)
    print("🔐 AWS SECURITY LAB - S3 Security Checker")
    print("="*60)
    print("\n⚠️  Requires AWS credentials configured\n")
    
    profile = input("AWS profile name (default): ").strip() or None
    
    checker = S3SecurityChecker(profile_name=profile)
    checker.run_full_audit()

if __name__ == "__main__":
    main()