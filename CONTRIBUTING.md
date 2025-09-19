# Contributing to AuditKit

First off, thanks for taking the time to contribute! This tool exists because compliance software is stupidly expensive, and every improvement helps someone avoid a $50k consultant fee.

## 🎯 What We Need Most

### High Priority
1. **More AWS Checks** - We only cover basics. Need EBS, Lambda, API Gateway, etc.
2. **Azure Support** - Many companies use Azure. Even basic checks would help.
3. **GCP Support** - Complete the big three cloud providers.
4. **Better Reporting** - PDF generation, Excel exports, better formatting.

### Medium Priority
- More SOC2 control mappings
- ISO 27001 control mappings
- PCI DSS checks
- Kubernetes/container scanning
- Auto-remediation for safe fixes

### Always Welcome
- Bug fixes
- Documentation improvements
- Performance optimizations
- Test coverage

## 🚀 Getting Started

1. Fork the repo
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Make your changes
4. Test thoroughly (`go test ./...`)
5. Commit (`git commit -m 'Add some AmazingFeature'`)
6. Push (`git push origin feature/AmazingFeature`)
7. Open a Pull Request

## 📝 Code Guidelines

### Go Code Style
- Follow standard Go formatting (`go fmt`)
- Keep functions small and focused
- Add comments for complex logic
- Include error handling

### Adding New Checks
When adding a new compliance check:

```go
// Example structure for a new check
func (s *AWSScanner) checkNewService(ctx context.Context) ([]ScanResult, error) {
    var results []ScanResult
    
    // 1. Call AWS API
    // 2. Evaluate against SOC2 control
    // 3. Return clear pass/fail with remediation
    
    results = append(results, ScanResult{
        Control:     "CC6.X",  // SOC2 control ID
        Status:      "FAIL",   // or "PASS"
        Severity:    "HIGH",   // CRITICAL, HIGH, MEDIUM, LOW
        Evidence:    "What we found",
        Remediation: "How to fix it (specific command)",
    })
    
    return results, nil
}
```

### Commit Messages
- Use present tense ("Add feature" not "Added feature")
- Keep first line under 50 characters
- Reference issues and pull requests

## 🧪 Testing

### Running Tests
```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific test
go test -run TestCheckS3Buckets ./pkg/aws
```

### Manual Testing
Before submitting:
1. Build the binary: `go build -o auditkit cmd/auditkit/main.go`
2. Test with real AWS account (with minimal permissions)
3. Test with missing credentials (should fail gracefully)
4. Test all output formats (text, json, html)

## 📊 Adding Support for New Cloud Providers

If you're adding Azure or GCP support:

1. Create new package: `pkg/azure/scanner.go` or `pkg/gcp/scanner.go`
2. Implement the same interface as AWS scanner
3. Map to SOC2 controls (keep consistent with AWS mappings)
4. Update main.go to support new provider
5. Document required permissions in README

Example structure:
```
scanner/
└── pkg/
    ├── aws/
    │   └── scanner.go
    ├── azure/        # New
    │   └── scanner.go
    └── gcp/          # New
        └── scanner.go
```

## 🐛 Reporting Bugs

Open an issue with:
- Go version (`go version`)
- AWS CLI version (`aws --version`)
- Exact error message
- Steps to reproduce
- Expected vs actual behavior

## 💡 Suggesting Features

Open an issue with:
- Use case (why you need it)
- Expected behavior
- Example output
- Which compliance framework it maps to

## ⚠️ Security

If you find a security vulnerability:
- DO NOT open a public issue
- Email admin@auditkit.io with details
- Allow 48 hours for response

## 📜 License

By contributing, you agree that your contributions will be licensed under Apache 2.0.

## ❓ Questions?

- Open an issue for general questions
- Tag @guardian-nexus for urgent items
- Join discussions in existing issues

## 🙏 Recognition

Contributors will be added to the README. Every contribution matters - even fixing typos helps someone.

Remember: The goal is to make compliance accessible. Keep it simple, make it work, document it well.
