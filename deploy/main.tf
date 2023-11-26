# Open Terraform
terraform { 
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.16"
    }
  }

  required_version = ">= 1.2.0"
}

# Create a port for the API
variable "api_port" {
  description = "The port for your API"
  type        = number 
  default     = 8080
}

# Select AWS as provider
provider "aws" {
  region = "us-east-2"
}

### Start creating the resources

# Create a EC2 instance
resource "aws_instance" "my_instance" {
  ami           = "ami-0e83be366243f524a" # AMI ID for Ubuntu 20.04 LTS (free tier)
  instance_type = "t2.micro"
  key_name               = "ClavesPemE1" # Select the keys
  vpc_security_group_ids = [aws_security_group.my_security_group.id]

  # user_data is used to run an script after provisioning the instance (Obtenido de la ayudantía)
  user_data = "${file("./scripts/deployment.sh")}"

  tags = {
    Name = "ayudantia-iaac"
  }
}

# Create and asing an elastic IP to de EC2 instance
resource "aws_eip" "my_eip" {
  instance = aws_instance.my_instance.id
}

# Create a segurity group to open ports
resource "aws_security_group" "my_security_group" {
  name        = "my_security_group"
  description = "Security group for SSH access"

  ingress {
    from_port   = 22 
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
}

# Create an empty zip file to upload to my lambda function
data "archive_file" "empty_zip" {
  type        = "zip"
  output_path = "./lambda/empty.zip"

  source {
    content = ""
    filename = "empty.txt"
  }
}

# Create my lambda function 
resource "aws_lambda_function" "my_lambda_function" {
  function_name = "my_lambda_function"
  handler       = "index.handler"
  runtime       = "nodejs14.x"
  filename      = data.archive_file.empty_zip.output_path

  role = aws_iam_role.lambda_role.arn
}

# Create an IAM role to upload to the lambda function
resource "aws_iam_role" "lambda_role" {
  name = "lambda-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = "sts:AssumeRole",
      Effect = "Allow",
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

# Create the API gateway
resource "aws_api_gateway_rest_api" "my_api_gateway" {
  name        = "my_api_gateway"
  description = "Api gateway linked to ec2 instance"
}

#Create a resource to the API gateway
resource "aws_api_gateway_resource" "my_resource" {
  rest_api_id = aws_api_gateway_rest_api.my_api_gateway.id
  parent_id   = aws_api_gateway_rest_api.my_api_gateway.root_resource_id
  path_part   = "/my-api"
}

# Create an API Gateway method for the integration resource
resource "aws_api_gateway_method" "my_method" {
  rest_api_id   = aws_api_gateway_rest_api.my_api_gateway.id
  resource_id   = aws_api_gateway_resource.my_resource.id
  http_method   = "GET"
  authorization = "NONE"
}

# Create the API Gateway integration for the resource
resource "aws_api_gateway_integration" "my_integration" {
  rest_api_id             = aws_api_gateway_rest_api.my_api_gateway.id
  resource_id             = aws_api_gateway_resource.my_resource.id
  http_method             = aws_api_gateway_method.my_method.http_method
  integration_http_method = "POST"  # Replace with the HTTP method expected by your Lambda
  type                    = "HTTP_PROXY"
  uri                     = "http://${aws_eip.my_eip.public_ip}:${var.api_port}" # Use the Elastic IP
  passthrough_behavior    = "WHEN_NO_MATCH"
  connection_type         = "INTERNET"
}

# Create a method response
resource "aws_api_gateway_method_response" "my_method_response" {
  rest_api_id = aws_api_gateway_rest_api.my_api_gateway.id
  resource_id = aws_api_gateway_resource.my_resource.id
  http_method = aws_api_gateway_method.my_method.http_method
  status_code = "200"
}

# Create a response to the integration
resource "aws_api_gateway_integration_response" "my_integration_response" {
  rest_api_id = aws_api_gateway_rest_api.my_api_gateway.id
  resource_id = aws_api_gateway_resource.my_resource.id
  http_method = aws_api_gateway_method.my_method.http_method
  status_code = aws_api_gateway_method_response.my_method_response.status_code
}

# Create an API Gateway resource for the Lambda integration
resource "aws_api_gateway_resource" "my_lambda_integration_resource" {
  rest_api_id = aws_api_gateway_rest_api.my_api_gateway.id
  parent_id   = aws_api_gateway_rest_api.my_api_gateway.root_resource_id
  path_part   = "/lambda"
}

# Create the method to the lambda integration resource
resource "aws_api_gateway_method" "my_lambda_integration_method" {
  rest_api_id   = aws_api_gateway_rest_api.my_api_gateway.id
  resource_id   = aws_api_gateway_resource.my_lambda_integration_resource.id
  http_method   = "GET" 
  authorization = "NONE" 
}

# Create an integration to connect API Gateway to the Lambda function
resource "aws_api_gateway_integration" "my_lambda_integration" {
  rest_api_id             = aws_api_gateway_rest_api.my_api_gateway.id
  resource_id             = aws_api_gateway_resource.my_lambda_integration_resource.id
  http_method             = aws_api_gateway_method.my_lambda_integration_method.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.my_lambda_function.invoke_arn
}

# Create a method response for the Lambda integration
resource "aws_api_gateway_method_response" "my_lambda_method_response" {
  rest_api_id = aws_api_gateway_rest_api.my_api_gateway.id
  resource_id = aws_api_gateway_resource.my_lambda_integration_resource.id
  http_method = aws_api_gateway_method.my_lambda_integration_method.http_method
  status_code = "200"
}

# Create the response to the lambda integration
resource "aws_api_gateway_integration_response" "my_lambda_integration_response" {
  rest_api_id = aws_api_gateway_rest_api.my_api_gateway.id
  resource_id = aws_api_gateway_resource.my_lambda_integration_resource.id
  http_method = aws_api_gateway_method.my_lambda_integration_method.http_method
  status_code = aws_api_gateway_method_response.my_lambda_method_response.status_code
}

# Create an S3 bucket for the frontend files
resource "aws_s3_bucket" "my_frontend_bucket" {
  bucket = "my_frontend_bucket"
}

# Manage permissions (ACL) to the S3 bucket
resource "aws_s3_bucket_acl" "my_frontend_bucket_acl" {
  bucket = aws_s3_bucket.my_frontend_bucket.id
  acl = "public-read" 
}

# Create a cloudfront distribution to upload the S3 bucket
resource "aws_cloudfront_distribution" "my_frontend_distribution" {
  origin {
    domain_name = aws_s3_bucket.my_frontend_bucket.bucket_regional_domain_name
    origin_id   = "S3-${aws_s3_bucket.my_frontend_bucket.id}"
  }

  enabled             = true
  default_root_object = "index.html"

  viewer_certificate {
    cloudfront_default_certificate = true
    minimum_protocol_version       = "TLSv1.2_2019"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  default_cache_behavior {
    target_origin_id = "S3-${aws_s3_bucket.my_frontend_bucket.id}"
    viewer_protocol_policy = "redirect-to-https"  # Redirect HTTP requests to HTTPS

    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD", "OPTIONS"]

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }
}

# Output to dislay after `terraform apply`
output "elastic_ip" {
  value = aws_eip.my_eip.public_ip
}

output "ssh_command" {
  value = "ssh -i ${aws_instance.my_instance.key_name}.pem ubuntu@${aws_eip.my_eip.public_ip}"
}
