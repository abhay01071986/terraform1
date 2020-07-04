provider "aws" {
  region = "us-east-1"
  version= "~> 2.0"
}
resource "aws_instance" "MyfirstEC2instance_Terraform" {
  ami           = "ami-09d95fab7fff3776c"
  instance_type = "t2.micro"
  key_name = "ec2_keypair"
  iam_instance_profile = "${aws_iam_instance_profile.test_profile.name}"
}
# Creating Security Group and allowing Port 22 and 80
resource "aws_security_group" "allow_tls" {
  name        = "allow_tls"
  description = "Allow TLS inbound traffic"
  vpc_id      = "vpc-15af4a68"


  ingress {
    description = "TLS from VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "TLS from VPC2"
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

  tags = {
    Name = "allow_http"
  }
}
#Create policy for EC2 instance to access Cloudwatch service
resource "aws_iam_role_policy" "cwagent_policy" {
  name = "cwagent_policy"
  role = aws_iam_role.cwagent_role.id

  policy = <<-EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "cloudwatch:PutMetricData",
                "ec2:DescribeVolumes",
                "ec2:DescribeTags",
                "logs:PutLogEvents",
                "logs:DescribeLogStreams",
                "logs:DescribeLogGroups",
                "logs:CreateLogStream",
                "logs:CreateLogGroup"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ssm:GetParameter"
            ],
            "Resource": "arn:aws:ssm:*:*:parameter/AmazonCloudWatch-*"
        }
    ]
}
  EOF
}
#Attaching policy with IAM role
resource "aws_iam_role" "cwagent_role" {
  name = "cwagent_role"

  assume_role_policy = <<-EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": "sts:AssumeRole",
        "Principal": {
          "Service": "ec2.amazonaws.com"
        },
        "Effect": "Allow",
        "Sid": ""
      }
    ]
  }
  EOF
}
#Attaching Role with Ec2 Instance
resource "aws_iam_instance_profile" "test_profile" {
  name = "test_profile"
  role = "${aws_iam_role.cwagent_role.name}"
}
#Connecting EC2 Instance to install Cloudwatch service
resource "null_resource" "ec2-ssh-connection" {
  connection {
    host        = "${aws_instance.MyfirstEC2instance_Terraform.public_ip}"
    type        = "ssh"
    port        = 22
    user        = "ec2-user"
    private_key = "${file("ec2_keypair.pem")}"
    timeout     = "1m"
    agent       = false
  }
  provisioner "file" {
    # cp config.json ec2-user@public_ip:/var/config.json
    source      = "config.json"
    destination = "/home/ec2-user/config.json"
  }
  provisioner "remote-exec" {
    inline = [
      "sudo yum update -y",
      "wget https://s3.amazonaws.com/amazoncloudwatch-agent/amazon_linux/amd64/latest/amazon-cloudwatch-agent.rpm",
      "sudo rpm -U ./amazon-cloudwatch-agent.rpm",
      "sudo cp /home/ec2-user/config.json /opt/aws/amazon-cloudwatch-agent/bin/config.json",
      "sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/bin/config.json",
      "sudo amazon-cloudwatch-agent-ctl -a fetch-config",
    ]
  }
}

#Connecting SG with EC2 Instance
resource "aws_network_interface_sg_attachment" "sg_attachment" {
  security_group_id    = "${aws_security_group.allow_tls.id}"
  network_interface_id = "${aws_instance.MyfirstEC2instance_Terraform.primary_network_interface_id}"
}

#Creating SNS topic
resource "aws_sns_topic" "user_updates" {
  name = "user-updates-topic"
}
#Creating Cloudwatch Alarm for Mem usage
resource "aws_cloudwatch_metric_alarm" "high_mem_alarm" {
  alarm_name = "high_mem_alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods = "2"
  metric_name = "MEMUtilization"
  namespace = "CWAgent"
  period = "120"
  statistic = "Average"
  threshold = "80"
  insufficient_data_actions = []
  alarm_description = "EC2 MEM Utilization"
  alarm_actions = [
    aws_sns_topic.user_updates.arn]
  dimensions = {
    InstanceId = "${aws_instance.MyfirstEC2instance_Terraform.id}"
  }
}
