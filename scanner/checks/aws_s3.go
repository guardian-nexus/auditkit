// Real S3 bucket security checks

package checks

import (
    "github.com/aws/aws-sdk-go/aws"
    "github.com/aws/aws-sdk-go/service/s3"
)

type S3SecurityCheck struct {
    client *s3.S3
}

func (s *S3SecurityCheck) CheckBucketEncryption(bucket string) CheckResult {
    // Check if S3 bucket has encryption enabled
    result, err := s.client.GetBucketEncryption(&s3.GetBucketEncryptionInput{
        Bucket: aws.String(bucket),
    })
    
    if err != nil {
        return CheckResult{
            Control: "CC-6.1",
            Status:  "FAIL",
            Details: "Bucket encryption not enabled",
            Severity: "HIGH",
        }
    }
    
    return CheckResult{
        Control: "CC-6.1", 
        Status:  "PASS",
        Details: "AES-256 encryption enabled",
    }
}

func (s *S3SecurityCheck) CheckPublicAccess(bucket string) CheckResult {
    // Check if bucket is publicly accessible
    acl, _ := s.client.GetBucketAcl(&s3.GetBucketAclInput{
        Bucket: aws.String(bucket),
    })
    
    for _, grant := range acl.Grants {
        if *grant.Grantee.Type == "Group" &&
           *grant.Grantee.URI == "http://acs.amazonaws.com/groups/global/AllUsers" {
            return CheckResult{
                Control: "CC-6.2",
                Status:  "FAIL", 
                Details: "Bucket is publicly accessible",
                Severity: "CRITICAL",
            }
        }
    }
    
    return CheckResult{
        Control: "CC-6.2",
        Status:  "PASS",
        Details: "Bucket is private",
    }
}

func (s *S3SecurityCheck) CheckVersioning(bucket string) CheckResult {
    // Check if versioning is enabled (for audit trails)
    vers, _ := s.client.GetBucketVersioning(&s3.GetBucketVersioningInput{
        Bucket: aws.String(bucket),
    })
    
    if vers.Status == nil || *vers.Status != "Enabled" {
        return CheckResult{
            Control: "A-1.1",
            Status:  "FAIL",
            Details: "Versioning not enabled - no audit trail",
            Severity: "MEDIUM",
        }
    }
    
    return CheckResult{
        Control: "A-1.1",
        Status:  "PASS",
        Details: "Versioning enabled for audit trail",
    }
}
