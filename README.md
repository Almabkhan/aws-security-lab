# 🔐 AWS Security Lab

A comprehensive AWS security auditing toolkit for educational purposes.

## ⚠️ IMPORTANT DISCLAIMER

**This toolkit is for educational purposes ONLY.**

- Use only on your own AWS accounts
- Never test on production accounts without authorization
- Always follow AWS acceptable use policy

## 🎯 Purpose

Learn about:

- AWS S3 bucket security
- IAM user and policy security
- Cloud security best practices
- Security auditing methodologies

## 📦 Components

### 1. S3 Security Checker (`s3_security.py`)

- Checks bucket public access
- Verifies encryption settings
- Audits versioning configuration
- Checks access logging
- Reports security issues with fixes

### 2. IAM Security Auditor (`iam_audit.py`)

- MFA enforcement check
- Access key age monitoring
- Password policy validation
- User permission analysis

### 3. Main Security Checker (`security_check.py`)

- Interactive menu interface
- Runs all security checks
- AWS credential validation

## 🚀 Installation

```bash
# Clone repository
git clone https://github.com/Almabkhan/aws-security-lab
cd aws-security-lab

# Install dependencies
pip install -r requirements.txt

# Configure AWS credentials
aws configure
