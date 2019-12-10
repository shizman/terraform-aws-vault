terraform {
  required_version = ">= 0.11.10"
}

/*------------------------------------------------------------------------------
The Vault cluster is either built as var.vault_cluster_size instances or as a
var.vault_cluster_size[min|max|des] instance ASG depending on the use of the
var.use_asg boolean.
------------------------------------------------------------------------------
------------------------------------------------------------------------------
 This is the instance build for the Vault infra without an ASG. This is
defined only if the variable var.use_asg = false (default)
------------------------------------------------------------------------------*/

resource "aws_instance" "vault-instance" {
  ami                         = "${var.vault_ami_id}"
  count                       = "${(var.use_asg ? 0 : var.vault_cluster_size)}"
  instance_type               = "${var.instance_type}"
  iam_instance_profile        = "${aws_iam_instance_profile.cluster_server.id}"
  associate_public_ip_address = false
  key_name                    = "${var.ssh_key_name}"
  vpc_security_group_ids      = ["${concat(var.additional_sg_ids, list(aws_security_group.vault_cluster_int.id))}"]
  subnet_id                   = "${element(var.private_subnets, count.index)}"
  user_data                   = "${data.template_file.vault_user_data.rendered}"

  tags = {
    Name                        = "vault_server-${count.index}"
    VAULT_CLUSTER_TAG           = "${var.vault_cluster_tag}"
    CONSUL_STORAGE_CLUSTER_TAG  = "${var.consul_cluster_tag}"
    Function                    = "vault_server"
  }
}

/*------------------------------------------------------------------------------
 This is the instance build for the Consul infra. If the var.use_asg is set to
 true then this cluster will be inside an ASG otherwise it will be made up of
 var.consul_cluster_size nodes
------------------------------------------------------------------------------*/

resource "aws_instance" "consul-instance" {
  ami                         = "${var.consul_ami_id}"
  count                       = "${(var.use_asg ? 0 : var.consul_cluster_size)}"
  instance_type               = "${var.instance_type}"
  iam_instance_profile        = "${aws_iam_instance_profile.cluster_server.id}"
  associate_public_ip_address = false
  key_name                    = "${var.ssh_key_name}"
  vpc_security_group_ids      = ["${concat(var.additional_sg_ids, list(aws_security_group.vault_cluster_int.id))}"]
  user_data                   = "${data.template_file.consul_user_data.rendered}"
  subnet_id                   = "${element(var.private_subnets, count.index)}"

  tags = {
    Name                       = "consul_storage-${count.index}"
    CONSUL_STORAGE_CLUSTER_TAG = "${var.consul_cluster_tag}"
    Function                   = "consul_server"
  }
}

/*------------------------------------------------------------------------------
This is the configuration for the Vault ASG. This is defined only if the
variable var.use_asg = true
------------------------------------------------------------------------------*/

resource "aws_launch_configuration" "vault_instance_asg" {
  count                = "${(var.use_asg ? 1 : 0)}"
  name_prefix          = "${var.cluster_name}-"
  image_id             = "${var.vault_ami_id}"
  instance_type        = "${var.instance_type}"
  iam_instance_profile = "${aws_iam_instance_profile.cluster_server.id}"
  security_groups      = ["${concat(var.additional_sg_ids, list(aws_security_group.vault_cluster_int.id))}"]
  key_name             = "${var.ssh_key_name}"
  user_data            = "${data.template_file.vault_user_data.rendered}"
}

resource "aws_autoscaling_group" "vault_asg" {
  count                = "${(var.use_asg ? 1 : 0)}"
  name_prefix          = "${var.cluster_name}"
  launch_configuration = "${aws_launch_configuration.vault_instance_asg.name}"
  availability_zones   = ["${var.availability_zones}"]
  vpc_zone_identifier  = ["${var.private_subnets}"]

  min_size             = "${var.vault_cluster_size}"
  max_size             = "${var.vault_cluster_size}"
  desired_capacity     = "${var.vault_cluster_size}"
  termination_policies = ["${var.termination_policies}"]

  health_check_type         = "EC2"
  health_check_grace_period = "${var.health_check_grace_period}"
  wait_for_capacity_timeout = "${var.wait_for_capacity_timeout}"

  enabled_metrics = ["${var.enabled_metrics}"]

  lifecycle {
    create_before_destroy = true
  }

  tags = [
    {
      key                 = "Name"
      value               = "vault_server"
      propagate_at_launch = true
    },
    {
      key                 = "VAULT_CLUSTER_TAG"
      value               = "${var.vault_cluster_tag}"
      propagate_at_launch = true
    },
    {
      key                 = "CONSUL_STORAGE_CLUSTER_TAG"
      value               = "${var.consul_cluster_tag}"
      propagate_at_launch = true
    },
    {
      key                 = "Function"
      value               = "vault_server"
      propagate_at_launch = true
    }
  ]
}

# Create a new load balancer attachment for ASG if ASG is used
resource "aws_autoscaling_attachment" "asg_attachment_vault" {
  count                  = "${(var.use_elb && var.use_asg ? 1 : 0)}"
  autoscaling_group_name = "${aws_autoscaling_group.vault_asg.id}"
  elb                    = "${aws_elb.vault_elb.id}"
}

/*------------------------------------------------------------------------------
This is the configuration for the Consul ASG. This is defined only if the
variable var.use_asg = true
------------------------------------------------------------------------------*/

resource "aws_launch_configuration" "consul_instance_asg" {
  count                = "${(var.use_asg ? 1 : 0)}"
  name_prefix          = "${var.cluster_name}-"
  image_id             = "${var.consul_ami_id}"
  instance_type        = "${var.instance_type}"
  iam_instance_profile = "${aws_iam_instance_profile.cluster_server.id}"
  security_groups      = ["${concat(var.additional_sg_ids, list(aws_security_group.vault_cluster_int.id))}"]
  key_name             = "${var.ssh_key_name}"
  user_data            = "${data.template_file.consul_user_data.rendered}"
}

resource "aws_autoscaling_group" "consul_asg" {
  count                = "${(var.use_asg ? 1 : 0)}"
  name_prefix          = "${var.cluster_name}"
  launch_configuration = "${aws_launch_configuration.consul_instance_asg.name}"
  availability_zones   = ["${var.availability_zones}"]
  vpc_zone_identifier  = ["${var.private_subnets}"]

  min_size             = "${var.consul_cluster_size}"
  max_size             = "${var.consul_cluster_size}"
  desired_capacity     = "${var.consul_cluster_size}"
  termination_policies = ["${var.termination_policies}"]

  health_check_type         = "EC2"
  health_check_grace_period = "${var.health_check_grace_period}"
  wait_for_capacity_timeout = "${var.wait_for_capacity_timeout}"

  enabled_metrics = ["${var.enabled_metrics}"]

  lifecycle {
    create_before_destroy = true
  }

  tags = [
    {
      key                 = "Name"
      value               = "consul_storage"
      propagate_at_launch = true
    },
    {
      key                 = "CONSUL_STORAGE_CLUSTER_TAG"
      value               = "${var.consul_cluster_tag}"
      propagate_at_launch = true
    },
    {
      key                 = "Function"
      value               = "consul_server"
      propagate_at_launch = true
    }
  ]
}

/*------------------------------------------------------------------------------
This is the configuration for the ELB. This is defined only if the variable
var.use_elb = true
------------------------------------------------------------------------------*/
resource "aws_elb" "vault_elb" {
  count                       = "${(var.use_elb ? 1 : 0)}"
  name_prefix                 = "elb-"
  internal                    = "${var.internal_elb}"
  cross_zone_load_balancing   = "${var.cross_zone_load_balancing}"
  idle_timeout                = "${var.idle_timeout}"
  connection_draining         = "${var.connection_draining}"
  connection_draining_timeout = "${var.connection_draining_timeout}"
  security_groups             = ["${aws_security_group.elb_sg.id}"]
  subnets                     = ["${split(",", var.internal_elb ? join(",", var.private_subnets) : join(",", var.public_subnets))}"]

  listener {
    lb_port           = "${var.lb_port}"
    lb_protocol       = "TCP"
    instance_port     = "${var.vault_api_port}"
    instance_protocol = "TCP"
  }

  listener {
    lb_port           = 8201
    lb_protocol       = "TCP"
    instance_port     = 8201
    instance_protocol = "TCP"
  }

  health_check {
    target              = "${var.health_check_protocol}:${var.vault_api_port}${var.health_check_path}"
    interval            = "${var.health_check_interval}"
    healthy_threshold   = "${var.health_check_healthy_threshold}"
    unhealthy_threshold = "${var.health_check_unhealthy_threshold}"
    timeout             = "${var.health_check_timeout}"
  }
}

resource "aws_security_group" "elb_sg" {
  count       = "${(var.use_elb || var.use_asg ? 1 : 0)}"
  description = "Enable vault UI and API access to the elb"
  name        = "elb-security-group"
  vpc_id      = "${var.vpc_id}"

  ingress {
    protocol    = "tcp"
    from_port   = 8200
    to_port     = 8201
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    protocol    = -1
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
}

/*--------------------------------------------------------------
Vault Cluster AWS KMS key
--------------------------------------------------------------*/
resource "aws_kms_key" "vault" {
  count                   = "${(var.use_auto_unseal ? 1 : 0)}"
  description             = "Vault unseal key"
  deletion_window_in_days = "${var.kms_deletion_days}"
  enable_key_rotation     = "${var.kms_key_rotate}"

  tags {
    Name = "vault-kms-unseal-${var.cluster_name}"
  }
}

/*--------------------------------------------------------------
Vault Cluster Instance Security Group
--------------------------------------------------------------*/

resource "aws_security_group" "vault_cluster_int" {
  name        = "vault_cluster_int"
  description = "The SG for vault Servers Internal comms"
  vpc_id      = "${var.vpc_id}"
}

/*--------------------------------------------------------------
Vault Cluster Internal Security Group Rules
Note the Consul ports are set to the 7xxx range to isolate the Consul
storage cluster
--------------------------------------------------------------*/
resource "aws_security_group_rule" "vault_cluster_allow_elb_820x_tcp" {
  count                    = "${(var.use_elb || var.use_asg ? 1 : 0)}"
  type                     = "ingress"
  from_port                = 8200
  to_port                  = 8201
  protocol                 = "tcp"
  source_security_group_id = "${aws_security_group.elb_sg.id}"
  description              = "Vault API port between elb and servers"
  security_group_id        = "${aws_security_group.vault_cluster_int.id}"
}

resource "aws_security_group_rule" "vault_cluster_allow_self_7300-7302_tcp" {
  type              = "ingress"
  from_port         = 7300
  to_port           = 7302
  protocol          = "tcp"
  self              = true
  description       = "Consul gossip protocol between agents and servers"
  security_group_id = "${aws_security_group.vault_cluster_int.id}"
}

resource "aws_security_group_rule" "vault_cluster_allow_self_7301-7302_udp" {
  type              = "ingress"
  from_port         = 7301
  to_port           = 7302
  protocol          = "udp"
  self              = true
  description       = "Consul gossip protocol between agents and servers"
  security_group_id = "${aws_security_group.vault_cluster_int.id}"
}

resource "aws_security_group_rule" "vault_cluster_allow_self_8200_tcp" {
  type              = "ingress"
  from_port         = 8200
  to_port           = 8200
  protocol          = "tcp"
  self              = true
  description       = "Vault API port between agents and servers"
  security_group_id = "${aws_security_group.vault_cluster_int.id}"
}

resource "aws_security_group_rule" "vault_cluster_allow_self_8201_tcp" {
  type              = "ingress"
  from_port         = 8201
  to_port           = 8201
  protocol          = "tcp"
  self              = true
  description       = "Vault listen port between servers"
  security_group_id = "${aws_security_group.vault_cluster_int.id}"
}

resource "aws_security_group_rule" "vault_cluster_allow_self_7500_tcp" {
  type              = "ingress"
  from_port         = 7500
  to_port           = 7501
  protocol          = "tcp"
  self              = true
  description       = "Consul API port between agents and servers"
  security_group_id = "${aws_security_group.vault_cluster_int.id}"
}

resource "aws_security_group_rule" "vault_cluster_allow_self_7600_tcp" {
  type              = "ingress"
  from_port         = 7600
  to_port           = 7600
  protocol          = "tcp"
  self              = true
  description       = "Consul DNS port between agents and servers"
  security_group_id = "${aws_security_group.vault_cluster_int.id}"
}

resource "aws_security_group_rule" "vault_cluster_allow_egress_all" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = "${aws_security_group.vault_cluster_int.id}"
}

/*------------------------------------------------------------------------------
 This is the IAM profile setup for the cluster servers to allow the Consul
 servers to join a cluster.
------------------------------------------------------------------------------*/
resource "aws_iam_instance_profile" "cluster_server" {
  name = "cluster-server-${var.cluster_name}"
  role = "${aws_iam_role.cluster_server_role.name}"
}

resource "aws_iam_role" "cluster_server_role" {
  name               = "cluster-server-${var.cluster_name}"
  path               = "/"
  assume_role_policy = "${file("${path.module}/provisioning/files/cluster-server-role.json")}"
}

resource "aws_iam_role_policy" "cluster_server" {
  name   = "cluster-server-${var.cluster_name}"
  role   = "${aws_iam_role.cluster_server_role.id}"
  policy = "${file("${path.module}/provisioning/files/cluster-server-role-policy.json")}"
}

/*--------------------------------------------------------------
KMS IAM Role and Policy to allow access to the KMS key from Vault servers to
utilise auto-unseal
--------------------------------------------------------------*/
data "template_file" "vault_kms_unseal" {
  count    = "${(var.use_auto_unseal ? 1 : 0)}"
  template = "${file("${path.module}/provisioning/templates/kms-access-role.json.tpl")}"

  vars {
    kms_arn = "${aws_kms_key.vault.arn}"
  }
}

resource "aws_iam_role_policy" "kms-access" {
  count  = "${(var.use_auto_unseal ? 1 : 0)}"
  name   = "kms-access-${var.cluster_name}"
  role   = "${aws_iam_role.cluster_server_role.id}"
  policy = "${data.template_file.vault_kms_unseal.rendered}"
}

/*--------------------------------------------------------------
This is the set up of the user data template file for the install
--------------------------------------------------------------*/
data "template_file" "vault_user_data" {
  template = "${file("${path.module}/provisioning/templates/install-vault.sh.tpl")}"

  vars {
    use_userdata        = "${var.use_userdata}"
    vault_binary           = "${var.vault_binary}"
    vault_version       = "${var.vault_version}"
    consul_binary          = "${var.consul_binary}"
    consul_version      = "${var.consul_version}"
    consul_cluster_tag         = "${var.consul_cluster_tag}"
    consul_cluster_size = "${var.consul_cluster_size}"
  }
}

data "template_file" "consul_user_data" {
  template = "${file("${path.module}/provisioning/templates/install-consul.sh.tpl")}"

  vars {
    use_userdata        = "${var.use_userdata}"
    consul_version      = "${var.consul_version}"
    consul_binary          = "${var.consul_binary}"
    consul_cluster_tag         = "${var.consul_cluster_tag}"
    consul_cluster_size = "${var.consul_cluster_size}"
  }
}
