
# AWS Security and Compliance Checklist

This checklist ensures best practices for AWS security and compliance across different services.

## **1. Identity and Access Management (IAM)**

### **aws_iam_user**
- [ ] **HIGH** - Ensure multi-factor authentication (MFA) is enabled for all IAM users with a console password.
- [ ] **MEDIUM** - Ensure IAM users receive permissions only through groups.

### **aws_iam_policy**
- [ ] **HIGH** - Ensure IAM policies do not allow wildcard `*` in `Action` and `NotResource`.
- [ ] **HIGH** - Ensure policies that allow full `*:*` privileges are not attached.

### **aws_iam_access_key**
- [ ] **HIGH** - Ensure no root user access key exists.
- [ ] **MEDIUM** - Ensure access keys are rotated every 90 days.

---

## **2. AWS Key Management Service (KMS)**
- [ ] **HIGH** - Ensure rotation is enabled for customer-created symmetric CMKs.
- [ ] **HIGH** - Ensure every IAM policy attached to KMS keys has a defined principal.

---

## **3. AWS Lambda**
- [ ] **HIGH** - Ensure environment variables are encrypted using KMS keys.
- [ ] **MEDIUM** - Ensure Lambda function URLs use IAM authentication.
- [ ] **LOW** - Ensure Lambda functions are configured with a Dead Letter Queue (DLQ).

---

## **4. AWS Load Balancing**
### **aws_lb**
- [ ] **MEDIUM** - Ensure access logging is enabled.
- [ ] **HIGH** - Ensure at least one HTTPS listener is configured.

---

## **5. AWS Networking**
### **aws_vpc**
- [ ] **MEDIUM** - Ensure the default VPC is not used.
- [ ] **LOW** - Ensure VPC flow logging is enabled.

### **aws_subnet**
- [ ] **MEDIUM** - Ensure public IP on launch is disabled.

---

## **6. Amazon Elastic Kubernetes Service (EKS)**
### **aws_eks_cluster**
- [ ] **HIGH** - Ensure the API server endpoint is private or restricted.
- [ ] **HIGH** - Ensure EKS control plane logging is enabled.
- [ ] **HIGH** - Ensure RBAC policies restrict access to sensitive resources.
- [ ] **HIGH** - Ensure IAM roles assigned to worker nodes follow least privilege.
- [ ] **MEDIUM** - Ensure automatic node upgrades are enabled.
- [ ] **MEDIUM** - Ensure Kubernetes audit logs are stored in AWS CloudWatch.

### **aws_eks_node_group**
- [ ] **HIGH** - Ensure IAM roles assigned to worker nodes have least privilege.
- [ ] **HIGH** - Ensure security groups restrict direct access to worker nodes.
- [ ] **MEDIUM** - Ensure Kubernetes Secrets are encrypted with KMS.

---

## **7. Amazon Elastic Container Service (ECS)**
### **aws_ecs_cluster**
- [ ] **HIGH** - Ensure Fargate tasks use encrypted ephemeral storage.
- [ ] **HIGH** - Ensure task execution roles follow least privilege.
- [ ] **MEDIUM** - Ensure logging for ECS tasks is enabled with AWS CloudWatch.
- [ ] **MEDIUM** - Ensure ECS container insights are enabled.

### **aws_ecs_service**
- [ ] **HIGH** - Ensure ECS services use IAM roles with least privilege.
- [ ] **MEDIUM** - Ensure load balancers use HTTPS.

---

## **8. Database Security and Logging**
### **aws_rds_instance**
- [ ] **HIGH** - Ensure encryption is enabled for RDS instances.
- [ ] **HIGH** - Ensure IAM authentication is enabled for RDS.
- [ ] **HIGH** - Ensure database backups are enabled and retained for at least 7 days.
- [ ] **MEDIUM** - Ensure enhanced monitoring is enabled for RDS.
- [ ] **MEDIUM** - Ensure database audit logging is enabled.

### **aws_rds_cluster**
- [ ] **HIGH** - Ensure encryption is enabled for Aurora clusters.
- [ ] **HIGH** - Ensure automatic minor version upgrades are enabled.
- [ ] **MEDIUM** - Ensure cluster parameter groups enforce TLS.

### **aws_dynamodb_table**
- [ ] **HIGH** - Ensure DynamoDB encryption at rest is enabled.
- [ ] **HIGH** - Ensure point-in-time recovery is enabled.
- [ ] **MEDIUM** - Ensure DynamoDB stream logging is enabled.

---

## **9. AWS Cloud Logging and Monitoring**
### **aws_cloudtrail**
- [ ] **HIGH** - Ensure CloudTrail is enabled in all AWS Regions.
- [ ] **HIGH** - Ensure CloudTrail logs are encrypted with KMS.
- [ ] **HIGH** - Ensure CloudTrail logs are stored in an S3 bucket with access logging enabled.

### **aws_config**
- [ ] **HIGH** - Ensure AWS Config is enabled for compliance tracking.
- [ ] **HIGH** - Ensure AWS Config rules monitor security groups and IAM policy changes.

### **aws_cloudwatch_log_group**
- [ ] **HIGH** - Ensure CloudWatch log groups have retention policies set.
- [ ] **MEDIUM** - Ensure alarms are configured for unusual IAM activity.
- [ ] **LOW** - Ensure CloudWatch metrics monitor API request anomalies.

---

## **How to Use**
1. Clone this repository.
2. Review each compliance check and mark items as completed.
3. Share this checklist with clients for validation and audit purposes.
