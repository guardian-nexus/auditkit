module github.com/guardian-nexus/auditkit/scanner

go 1.23.0

toolchain go1.24.7

require (
	// Azure SDK
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.19.1
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.12.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault v1.4.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor v0.11.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql v1.2.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage v1.8.1
	// AWS SDK v2
	github.com/aws/aws-sdk-go-v2 v1.39.0
	github.com/aws/aws-sdk-go-v2/config v1.31.8
	github.com/aws/aws-sdk-go-v2/service/autoscaling v1.59.1
	github.com/aws/aws-sdk-go-v2/service/backup v1.47.4
	github.com/aws/aws-sdk-go-v2/service/cloudtrail v1.53.4
	github.com/aws/aws-sdk-go-v2/service/cloudwatch v1.50.1
	github.com/aws/aws-sdk-go-v2/service/configservice v1.58.0
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.253.0
	github.com/aws/aws-sdk-go-v2/service/guardduty v1.64.0
	github.com/aws/aws-sdk-go-v2/service/iam v1.47.5
	github.com/aws/aws-sdk-go-v2/service/inspector2 v1.44.4
	github.com/aws/aws-sdk-go-v2/service/kms v1.45.3
	github.com/aws/aws-sdk-go-v2/service/lambda v1.77.4
	github.com/aws/aws-sdk-go-v2/service/organizations v1.45.1
	github.com/aws/aws-sdk-go-v2/service/rds v1.107.0
	github.com/aws/aws-sdk-go-v2/service/s3 v1.88.1
	github.com/aws/aws-sdk-go-v2/service/securityhub v1.64.2
	github.com/aws/aws-sdk-go-v2/service/sns v1.38.3
	github.com/aws/aws-sdk-go-v2/service/ssm v1.64.4
	github.com/aws/aws-sdk-go-v2/service/sts v1.38.4

	// Report generation
	github.com/jung-kurt/gofpdf v1.16.2
)

require (
	// Azure indirect dependencies
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.11.2 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v1.5.0 // indirect
	// AWS indirect dependencies
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.1 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.18.12 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.7 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.7 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.7 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.3 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.8.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.19.7 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.29.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.34.4 // indirect
	github.com/aws/smithy-go v1.23.0 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	golang.org/x/crypto v0.41.0 // indirect
	golang.org/x/net v0.43.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
	golang.org/x/text v0.28.0 // indirect
)

require (
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization v1.0.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute v1.0.0
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork v1.1.0
)
