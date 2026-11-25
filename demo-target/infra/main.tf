# Acme Health (fictional) - production infrastructure
provider "aws" {
  region = "eu-central-1"
}

# ---------- Storage ----------
resource "aws_s3_bucket" "patient_records" {
  bucket = "acme-patient-records-prod"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "patient_records" {
  bucket = aws_s3_bucket.patient_records.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "patient_records" {
  bucket                  = aws_s3_bucket.patient_records.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ---------- Network ----------
resource "aws_security_group" "web" {
  name   = "web-sg"
  vpc_id = var.vpc_id

  ingress {
    description = "HTTPS from internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH from VPN only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.20.0.0/16"]
  }
}

# ---------- Database ----------
resource "aws_db_instance" "main" {
  identifier          = "acme-prod-db"
  engine              = "postgres"
  instance_class      = "db.t3.medium"
  username            = "acme_admin"
  password            = var.db_password
  storage_encrypted   = true
  publicly_accessible = false
  skip_final_snapshot = false
}

# ---------- IAM ----------
resource "aws_iam_user" "deploy" {
  name = "ci-deploy"
}

resource "aws_iam_policy" "deploy" {
  name = "ci-deploy-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}
