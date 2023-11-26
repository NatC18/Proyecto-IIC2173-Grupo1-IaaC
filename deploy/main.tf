# AWS Docs: https://registry.terraform.io/providers/hashicorp/aws/latest/docs

# Steps:
# 0. Select a provider                                                          https://registry.terraform.io/providers/hashicorp/aws/latest
# 1. Create an EC2 instance                                                     https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance
# 2. Create Elastic IP and assign                                               https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eip
# 3. Create a security group to open ports                                      https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group
# optional. Define output to display after apply                                https://developer.hashicorp.com/terraform/language/values/outputs

terraform { 
  # All providers: https://registry.terraform.io/browse/providers?product_intent=terraform
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.16"
    }
  }

  required_version = ">= 1.2.0"
}

variable "api_port" {
  description = "The port for your API"
  type        = number  # Adjust the type according to your needs (number, string, etc.)
  default     = 8080    # Set a default value or change it to your desired port number
}

# 0. Select a provider 
provider "aws" { #TODO: este es el provedor, hay muchos provedores y hay que especificarlo
  region = "us-east-2"
}

#TODO: empezar a crear lso recursos

# 1. Create a new EC2 instance
resource "aws_instance" "my_instance" { # ami es símil a imagen de docker, es si es ubuntu por ejemplo
  ami           = "ami-0e83be366243f524a" # AMI ID for Ubuntu 20.04 LTS (free tier) # Find an AMI: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/finding-an-ami.html
  instance_type = "t2.micro"
  #   key_name      = aws_key_pair.my_key_pair.key_name
  key_name               = "ClavesPemE1"
  vpc_security_group_ids = [aws_security_group.my_security_group.id]

  # user_data is used to run an script after provisioning the instance
  user_data = "${file("./scripts/deployment.sh")}"
  tags = {
    Name = "ayudantia-iaac"
  }
}

# 2. Create and assign Elastic IP
resource "aws_eip" "my_eip" {
  instance = aws_instance.my_instance.id
}

# 3. Create a security group to open ports
resource "aws_security_group" "my_security_group" {
  name        = "my_security_group"
  description = "Security group for SSH access"

  ingress {
    from_port   = 22 # Para conectarme al ssh
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port        = 0 # Para conectarme a internet
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
}  #TODO: puedo conectarme a mas puertos (por ejemplo el 80 80) para conectarme a HTTP 

data "archive_file" "empty_zip" {
  type        = "zip"
  output_path = "./lambda/empty.zip"  # Replace with your desired path
  source {
    content = ""
    filename = "empty.txt"
  }
}

resource "aws_lambda_function" "my_lambda_function" {
  function_name = "my_lambda_function"
  handler       = "index.handler"
  runtime       = "nodejs14.x"
  filename      = data.archive_file.empty_zip.output_path  # Use the empty ZIP file


  # Lambda execution role
  role = aws_iam_role.lambda_role.arn

  # Optionally, set environment variables for your Lambda function
#   environment {
#     variables = {
#       EXAMPLE_VARIABLE = "example_value"
#     }
#   }
}

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

  # Attach necessary policies or permissions for your Lambda function here
  # For example, policies for accessing other AWS resources, CloudWatch logs, etc.
}

# Crear la API Gateway
resource "aws_api_gateway_rest_api" "my_api_gateway" {
  name        = "my_api_gateway"
  description = "Api gateway linked to ec2 instance"
}

resource "aws_api_gateway_resource" "my_resource" {
  rest_api_id = aws_api_gateway_rest_api.my_api_gateway.id
  parent_id   = aws_api_gateway_rest_api.my_api_gateway.root_resource_id
  path_part   = "/my-api" # e.g., /myapi

  # Create HTTP method(s) for your API (e.g., GET, POST, etc.)
}

# Create an API Gateway method for the Lambda integration resource
resource "aws_api_gateway_method" "my_method" {
  rest_api_id   = aws_api_gateway_rest_api.my_api_gateway.id
  resource_id   = aws_api_gateway_resource.my_resource.id
  http_method   = "GET"  # Replace with your desired HTTP method, e.g., GET, POST, etc.
  authorization = "NONE" # Or specify your desired authorization method
}

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
  status_code = "200"  # Replace with your expected status code
}

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
  path_part   = "/lambda"  # Replace with your desired path

  # Create HTTP method(s) for your API (e.g., GET, POST, etc.)
}

resource "aws_api_gateway_method" "my_lambda_integration_method" {
  rest_api_id   = aws_api_gateway_rest_api.my_api_gateway.id
  resource_id   = aws_api_gateway_resource.my_lambda_integration_resource.id
  http_method   = "GET"  # Replace with your desired HTTP method, e.g., GET, POST, etc.
  authorization = "NONE" # Or specify your desired authorization method
}

# Create an integration to connect API Gateway to the Lambda function
resource "aws_api_gateway_integration" "my_lambda_integration" {
  rest_api_id             = aws_api_gateway_rest_api.my_api_gateway.id
  resource_id             = aws_api_gateway_resource.my_lambda_integration_resource.id
  http_method             = aws_api_gateway_method.my_lambda_integration_method.http_method
  integration_http_method = "POST"  # Replace with the HTTP method expected by your Lambda
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.my_lambda_function.invoke_arn
}

# Create a method response for the Lambda integration
resource "aws_api_gateway_method_response" "my_lambda_method_response" {
  rest_api_id = aws_api_gateway_rest_api.my_api_gateway.id
  resource_id = aws_api_gateway_resource.my_lambda_integration_resource.id
  http_method = aws_api_gateway_method.my_lambda_integration_method.http_method
  status_code = "200"  # Replace with your expected status code
}


resource "aws_api_gateway_integration_response" "my_lambda_integration_response" {
  rest_api_id = aws_api_gateway_rest_api.my_api_gateway.id
  resource_id = aws_api_gateway_resource.my_lambda_integration_resource.id
  http_method = aws_api_gateway_method.my_lambda_integration_method.http_method
  status_code = aws_api_gateway_method_response.my_lambda_method_response.status_code
}

# Create an S3 bucket
resource "aws_s3_bucket" "my_frontend_bucket" {
  bucket = "my_frontend_bucket"
  # ... Add more configurations as needed
}

resource "aws_s3_bucket_acl" "my_frontend_bucket_acl" {
  bucket = aws_s3_bucket.my_frontend_bucket.id

  # Set the ACL rules
  acl = "public-read"  # Adjust the ACL as needed
  # ... Add more ACL rules if required
}

resource "aws_cloudfront_distribution" "my_frontend_distribution" {
  origin {
    domain_name = aws_s3_bucket.my_frontend_bucket.bucket_regional_domain_name
    origin_id   = "S3-${aws_s3_bucket.my_frontend_bucket.id}"
  }

  enabled             = true
  default_root_object = "index.html"  # Set the default file to load

  viewer_certificate {
    cloudfront_default_certificate = true
    minimum_protocol_version       = "TLSv1.2_2019"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"  # No geographic restrictions
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

  # Add more configurations as needed
}


# Output to dislay after `terraform apply`
output "elastic_ip" {
  value = aws_eip.my_eip.public_ip
}

output "ssh_command" {
  value = "ssh -i ${aws_instance.my_instance.key_name}.pem ubuntu@${aws_eip.my_eip.public_ip}"
}


# TODO: cuando termino, hago `terraform init` y luego `terraform validate` (ve sintaxis) y luego `terraform plan`-> Esto me va a dar el paso a paso de lo que se va a hacer (y hace un grafo)
# Luego se hace `terraform apply` para subir las cosas a AWS --> igual puede tirar errores
