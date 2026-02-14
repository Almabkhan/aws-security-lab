#!/usr/bin/env python3
"""
AWS IAM Security Auditor - Educational Tool
Audits IAM users, roles, and policies
"""

import boto3 # type: ignore
from botocore.exceptions import ClientError # type: ignore

class IAMAuditor:
    def __init__(self, profile_name=None):
        """Initialize IAM client"""
        if profile_name:
            self.session = boto3.Session(profile_name=profile_name)
        else:
            self.session = boto3.Session()
        
        self.iam = self.session.client('iam')
        self.issues = []
    
    def list_users(self):
        """List all IAM users"""
        try:
            response = self.iam.list_users()
            return response['Users']
        except ClientError as e:
            print(f"❌ Error listing users: {e}")
            return []
    
    def check_user_mfa(self, user):
        """Check if user has MFA enabled"""
        username = user['UserName']
        try:
            mfa = self.iam.list_mfa_devices(UserName=username)
            if not mfa['MFADevices']:
                self.issues.append({
                    'resource': f"User: {username}",
                    'issue': 'MFA not enabled',
                    'severity': 'HIGH',
                    'fix': 'Enable MFA for user'
                })
        except ClientError:
            pass
    
    def check_user_keys(self, user):
        """Check user access keys"""
        username = user['UserName']
        try:
            keys = self.iam.list_access_keys(UserName=username)
            for key in keys['AccessKeyMetadata']:
                if key['Status'] == 'Active':
                    # Check key age
                    create_date = key['CreateDate']
                    age_days = (boto3.session.datetime.now() - create_date).days
                    
                    if age_days > 90:
                        self.issues.append({
                            'resource': f"User: {username}",
                            'issue': f'Access key older than 90 days ({age_days} days)',
                            'severity': 'MEDIUM',
                            'fix': 'Rotate access keys'
                        })
        except ClientError:
            pass
    
    def check_password_policy(self):
        """Check account password policy"""
        try:
            policy = self.iam.get_account_password_policy()
            policy = policy['PasswordPolicy']
            
            if not policy.get('RequireUppercaseCharacters', False):
                self.issues.append({
                    'resource': 'Account',
                    'issue': 'Password policy: Uppercase not required',
                    'severity': 'MEDIUM',
                    'fix': 'Enable uppercase requirement'
                })
            if not policy.get('RequireLowercaseCharacters', False):
                self.issues.append({
                    'resource': 'Account',
                    'issue': 'Password policy: Lowercase not required',
                    'severity': 'MEDIUM',
                    'fix': 'Enable lowercase requirement'
                })
            if not policy.get('RequireNumbers', False):
                self.issues.append({
                    'resource': 'Account',
                    'issue': 'Password policy: Numbers not required',
                    'severity': 'MEDIUM',
                    'fix': 'Enable numbers requirement'
                })
            if not policy.get('RequireSymbols', False):
                self.issues.append({
                    'resource': 'Account',
                    'issue': 'Password policy: Symbols not required',
                    'severity': 'MEDIUM',
                    'fix': 'Enable symbols requirement'
                })
            if policy.get('MinimumPasswordLength', 0) < 8:
                self.issues.append({
                    'resource': 'Account',
                    'issue': f'Password policy: Min length {policy.get("MinimumPasswordLength", 0)} < 8',
                    'severity': 'MEDIUM',
                    'fix': 'Set minimum password length to 8+'
                })
        except ClientError:
            self.issues.append({
                'resource': 'Account',
                'issue': 'No password policy defined',
                'severity': 'HIGH',
                'fix': 'Configure password policy'
            })
    
    def run_audit(self):
        """Run complete IAM audit"""
        print("\n" + "="*60)
        print("🔑 AWS IAM SECURITY AUDIT")
        print("="*60)
        
        # Check password policy
        self.check_password_policy()
        
        # Check users
        users = self.list_users()
        print(f"\n👥 Found {len(users)} users to audit\n")
        
        for user in users:
            print(f"[*] Auditing user: {user['UserName']}")
            self.check_user_mfa(user)
            self.check_user_keys(user)
        
        self.generate_report()
    
    def generate_report(self):
        """Generate audit report"""
        print("\n" + "="*60)
        print("📊 IAM SECURITY AUDIT REPORT")
        print("="*60)
        
        if not self.issues:
            print("\n✅ No security issues found!")
            return
        
        # Group by severity
        severity_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2}
        self.issues.sort(key=lambda x: severity_order.get(x['severity'], 3))
        
        print(f"\n⚠️ Found {len(self.issues)} security issues:\n")
        
        for i, issue in enumerate(self.issues, 1):
            print(f"{i}. [{issue['severity']}] {issue['resource']}")
            print(f"   Issue: {issue['issue']}")
            print(f"   Fix: {issue['fix']}")
            print()

def main():
    print("="*60)
    print("🔐 AWS SECURITY LAB - IAM Security Auditor")
    print("="*60)
    print("\n⚠️  Requires AWS credentials configured\n")
    
    profile = input("AWS profile name (default): ").strip() or None
    
    auditor = IAMAuditor(profile_name=profile)
    auditor.run_audit()

if __name__ == "__main__":
    main()