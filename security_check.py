#!/usr/bin/env python3
"""
AWS Security Checker - Educational Tool
Main script to run all security checks
"""

import subprocess
import sys
import os

class AWSSecurityChecker:
    def __init__(self):
        self.checks = [
            {'name': 'S3 Bucket Security', 'script': 's3_security.py'},
            {'name': 'IAM Security', 'script': 'iam_audit.py'}
        ]
    
    def check_aws_credentials(self):
        """Check if AWS credentials are configured"""
        try:
            result = subprocess.run(
                ['aws', 'sts', 'get-caller-identity'],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                print("✅ AWS credentials configured")
                return True
            else:
                print("❌ AWS credentials not configured")
                return False
        except FileNotFoundError:
            print("❌ AWS CLI not installed")
            return False
    
    def run_all_checks(self):
        """Run all security checks"""
        print("="*60)
        print("🔐 AWS SECURITY LAB - Complete Security Check")
        print("="*60)
        
        if not self.check_aws_credentials():
            print("\nPlease configure AWS credentials first:")
            print("  aws configure")
            return
        
        print("\n🚀 Running security checks...\n")
        
        for check in self.checks:
            print(f"\n{'='*60}")
            print(f"📌 {check['name']}")
            print(f"{'='*60}")
            
            script_path = os.path.join(os.path.dirname(__file__), check['script'])
            result = subprocess.run([sys.executable, script_path])
            
            if result.returncode != 0:
                print(f"⚠️ {check['name']} completed with issues")
    
    def show_menu(self):
        """Show interactive menu"""
        while True:
            print("\n" + "="*60)
            print("📋 AWS SECURITY LAB MENU")
            print("="*60)
            print("1. Run all security checks")
            print("2. Check S3 buckets only")
            print("3. Check IAM only")
            print("4. Check AWS credentials")
            print("5. Exit")
            
            choice = input("\nEnter choice (1-5): ").strip()
            
            if choice == "1":
                self.run_all_checks()
            elif choice == "2":
                subprocess.run([sys.executable, 's3_security.py'])
            elif choice == "3":
                subprocess.run([sys.executable, 'iam_audit.py'])
            elif choice == "4":
                self.check_aws_credentials()
            elif choice == "5":
                print("\n👋 Stay secure!")
                break
            else:
                print("❌ Invalid choice")

def main():
    checker = AWSSecurityChecker()
    checker.show_menu()

if __name__ == "__main__":
    main()