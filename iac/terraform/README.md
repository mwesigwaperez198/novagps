# NOVA Terraform Example

This AWS example provisions:

- VPC with public/private subnets
- Managed EKS node group
- Encrypted managed PostgreSQL
- Encrypted object storage bucket for backups

Run:

```bash
terraform init
terraform plan -var='db_password=replace_me'
```

Production notes:

- Use AWS Secrets Manager or Vault for `db_password`.
- Add MSK or a managed Kafka provider when leaving local Kafka.
- Install ingress-nginx, cert-manager, external-dns, Prometheus, Grafana, Loki, and a service mesh if you require mTLS.
