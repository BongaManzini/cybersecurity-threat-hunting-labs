# AWS IMDSv2 Hardening & SSRF Defense Blueprint

**Target:** Amazon Web Services (AWS) EC2, ECS, and EKS  
**Threat Vector:** Server-Side Request Forgery (SSRF) to `http://169.254.169.254` (Capital One style data breach)

---

## 1. Vulnerability Mechanics: IMDSv1 vs IMDSv2

### The IMDSv1 Flaw
Under IMDSv1, requesting temporary AWS security credentials requires a simple `GET` request:
```bash
# IMDSv1 Vulnerable Request
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2-Role-Name
```
If a web application has an SSRF vulnerability (e.g., an unvalidated image proxy or PDF generation endpoint), an attacker can supply `http://169.254.169.254` as the URL and extract AWS Access Keys, Secret Keys, and Session Tokens.

### IMDSv2 Protection Mechanism
IMDSv2 introduces session-oriented requests requiring a **PUT request with a custom header** to retrieve a temporary session token:
```bash
# Phase 1: Request Session Token (Requires PUT and header)
TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"`

# Phase 2: Request Metadata using Token
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/
```
Because typical SSRF exploit vectors (image proxies, `<img>` tags, PDF renderers) can only execute `GET` requests and cannot inject custom HTTP headers like `X-aws-ec2-metadata-token-ttl-seconds`, IMDSv2 completely neutralizes standard SSRF credential exfiltration.

---

## 2. Enforcement via AWS CLI & Terraform

### Enforce IMDSv2 on Running EC2 Instances
```bash
aws ec2 modify-instance-metadata-options \
    --instance-id i-0123456789abcdef0 \
    --http-tokens required \
    --http-put-response-hop-limit 1 \
    --http-endpoint enabled
```

### Terraform Hardening Template
```hcl
resource "aws_instance" "hardened_app" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.medium"

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # Enforces IMDSv2
    http_put_response_hop_limit = 1          # Prevents container breakout to host metadata
    instance_metadata_tags      = "enabled"
  }
}
```
Setting `http_put_response_hop_limit = 1` ensures that network packets cannot cross container/pod network boundaries into the underlying EC2 host metadata service.
