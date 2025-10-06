terraform {
  required_version = ">= 1.2.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ---------------- Variables ----------------
variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "project_name" {
  type    = string
  default = "PathwayAI"
}

variable "vpc_cidr" {
  type    = string
  default = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  type    = list(string)
  default = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "private_subnet_cidrs" {
  type    = list(string)
  default = ["10.0.11.0/24", "10.0.12.0/24"]
}

variable "db_username" {
  type    = string
  default = "pathway_admin"
}

variable "db_password" {
  type      = string
  sensitive = true
  default   = "changemeDBPassword123!"
}

variable "db_instance_class" {
  type    = string
  default = "db.t4g.medium"
}

variable "redis_node_type" {
  type    = string
  default = "cache.t4g.small"
}

variable "container_image" {
  type    = string
  default = "public.ecr.aws/your-repo/pathwayai-backend:latest"
}

variable "cpu" {
  type    = number
  default = 512
}

variable "memory" {
  type    = number
  default = 1024
}

variable "desired_count" {
  type    = number
  default = 2
}

# ---------------- Locals ----------------
locals {
  public_cidrs  = { for idx, cidr in var.public_subnet_cidrs  : tostring(idx) => cidr }
  private_cidrs = { for idx, cidr in var.private_subnet_cidrs : tostring(idx) => cidr }
}

data "aws_availability_zones" "available" {}

# ---------------- Networking ----------------
resource "aws_vpc" "this" {
  cidr_block = var.vpc_cidr
  tags       = { Name = "${var.project_name}-vpc" }
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${var.project_name}-igw" }
}

resource "aws_subnet" "public" {
  for_each = local.public_cidrs
  vpc_id                  = aws_vpc.this.id
  cidr_block              = each.value
  map_public_ip_on_launch = true
  availability_zone       = data.aws_availability_zones.available.names[tonumber(each.key) % length(data.aws_availability_zones.available.names)]
  tags = { Name = "${var.project_name}-public-${each.key}" }
}

resource "aws_subnet" "private" {
  for_each = local.private_cidrs
  vpc_id                  = aws_vpc.this.id
  cidr_block              = each.value
  map_public_ip_on_launch = false
  availability_zone       = data.aws_availability_zones.available.names[tonumber(each.key) % length(data.aws_availability_zones.available.names)]
  tags = { Name = "${var.project_name}-private-${each.key}" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }
}

resource "aws_route_table_association" "public_assoc" {
  for_each       = aws_subnet.public
  subnet_id      = each.value.id
  route_table_id = aws_route_table.public.id
}

# ---------------- Security Groups ----------------
resource "aws_security_group" "alb" {
  name        = "${var.project_name}-alb-sg"
  vpc_id      = aws_vpc.this.id
  description = "Allow HTTP from internet to ALB"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "ecs" {
  name        = "${var.project_name}-ecs-sg"
  vpc_id      = aws_vpc.this.id
  description = "Allow ALB to ECS"

  ingress {
    from_port       = 3000
    to_port         = 3000
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "db" {
  name        = "${var.project_name}-db-sg"
  vpc_id      = aws_vpc.this.id
  description = "Allow ECS to Postgres"

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "redis" {
  name        = "${var.project_name}-redis-sg"
  vpc_id      = aws_vpc.this.id
  description = "Allow ECS to Redis"

  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ---------------- ALB + ECS ----------------
resource "aws_lb" "app" {
  name               = "${var.project_name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = [for s in aws_subnet.public : s.value.id]
}

resource "aws_lb_target_group" "tg" {
  name     = "${var.project_name}-tg"
  port     = 3000
  protocol = "HTTP"
  vpc_id   = aws_vpc.this.id

  health_check {
    path                = "/health"
    protocol            = "HTTP"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    matcher             = "200-399"
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.app.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tg.arn
  }
}

resource "aws_cloudwatch_log_group" "ecs" {
  name              = "/ecs/${var.project_name}"
  retention_in_days = 14
}

resource "aws_ecs_cluster" "this" {
  name               = "${var.project_name}-cluster"
  capacity_providers = ["FARGATE", "FARGATE_SPOT"]
}

data "aws_iam_policy_document" "ecs_task_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ecs_task_exec" {
  name               = "${var.project_name}-ecs-task-exec"
  assume_role_policy = data.aws_iam_policy_document.ecs_task_assume_role.json
}

resource "aws_iam_role_policy_attachment" "exec_policy" {
  role       = aws_iam_role.ecs_task_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_ecs_task_definition" "app" {
  family                   = "${var.project_name}-task"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = tostring(var.cpu)
  memory                   = tostring(var.memory)
  execution_role_arn       = aws_iam_role.ecs_task_exec.arn

  container_definitions = jsonencode([
    {
      name      = "api"
      image     = var.container_image
      essential = true
      portMappings = [{ containerPort = 3000, protocol = "tcp" }]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.ecs.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "api"
        }
      }
      environment = [
        { name = "DATABASE_URL", value = "REPLACE_WITH_RDS_ENDPOINT" },
        { name = "REDIS_URL",    value = "REPLACE_WITH_REDIS_ENDPOINT" }
      ]
    }
  ])
}

resource "aws_ecs_service" "app" {
  name            = "${var.project_name}-svc"
  cluster         = aws_ecs_cluster.this.id
  task_definition = aws_ecs_task_definition.app.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = [for s in aws_subnet.private : s.value.id]
    assign_public_ip = false
    security_groups  = [aws_security_group.ecs.id]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.tg.arn
    container_name   = "api"
    container_port   = 3000
  }

  depends_on = [aws_lb_listener.http]
}

# ---------------- RDS ----------------
resource "aws_db_subnet_group" "default" {
  name       = "${var.project_name}-dbsubnets"
  subnet_ids = [for s in aws_subnet.private : s.value.id]
}

resource "aws_db_instance" "postgres" {
  identifier             = "${var.project_name}-db"
  engine                 = "postgres"
  engine_version         = "15"
  instance_class         = var.db_instance_class
  allocated_storage      = 20
  username               = var.db_username
  password               = var.db_password
  db_subnet_group_name   = aws_db_subnet_group.default.name
  vpc_security_group_ids = [aws_security_group.db.id]
  skip_final_snapshot    = true
  multi_az               = false
  publicly_accessible    = false
  tags = { Name = "${var.project_name}-postgres" }
}

# ---------------- Redis (non-clustered) ----------------
resource "aws_elasticache_subnet_group" "redis" {
  name       = "${var.project_name}-redis-subnets"
  subnet_ids = [for s in aws_subnet.private : s.value.id]
}

resource "aws_elasticache_replication_group" "redis" {
  replication_group_id          = "${var.project_name}-rg"
  replication_group_description = "PathwayAI Redis replication"
  engine                        = "redis"
  node_type                     = var.redis_node_type
  number_cache_clusters         = 2
  automatic_failover_enabled    = true
  subnet_group_name             = aws_elasticache_subnet_group.redis.name
  security_group_ids            = [aws_security_group.redis.id]
  port                          = 6379
  tags = { Name = "${var.project_name}-redis" }
}

# ---------------- S3 + SQS ----------------
resource "aws_s3_bucket" "assets" {
  bucket        = "${var.project_name}-assets-${substr(md5(var.project_name), 0, 6)}"
  acl           = "private"
  force_destroy = false

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  tags = { Name = "${var.project_name}-s3" }
}

resource "aws_sqs_queue" "jobs" {
  name                        = "${var.project_name}-jobs.fifo"
  fifo_queue                  = true
  content_based_deduplication = true
  visibility_timeout_seconds  = 60
  tags = { Name = "${var.project_name}-jobs" }
}

# ---------------- IAM + Monitoring ----------------
resource "aws_iam_role_policy" "ecs_task_policy" {
  name = "${var.project_name}-ecs-task-policy"
  role = aws_iam_role.ecs_task_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
        Effect   = "Allow"
        Resource = [aws_s3_bucket.assets.arn, "${aws_s3_bucket.assets.arn}/*"]
      },
      {
        Action   = ["sqs:SendMessage", "sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
        Effect   = "Allow"
        Resource = aws_sqs_queue.jobs.arn
      }
    ]
  })
}

resource "aws_cloudwatch_metric_alarm" "ecs_cpu_high" {
  alarm_name          = "${var.project_name}-ecs-cpu-high"
  namespace           = "AWS/ECS"
  metric_name         = "CPUUtilization"
  statistic           = "Average"
  comparison_operator = "GreaterThanThreshold"
  threshold           = 80
  period              = 300
  evaluation_periods  = 2
  alarm_description   = "ECS cluster CPU > 80%"
}

# ---------------- Outputs ----------------
output "alb_dns" {
  value = aws_lb.app.dns_name
}

output "rds_endpoint" {
  value = aws_db_instance.postgres.address
}

output "redis_primary_endpoint" {
  value = aws_elasticache_replication_group.redis.primary_endpoint_address
}

output "s3_bucket" {
  value = aws_s3_bucket.assets.bucket
}

output "sqs_queue_url" {
  value = aws_sqs_queue.jobs.id
}
