# Vault AWS Module

This repo contains a module for how to deploy a [Vault](https://www.vaultproject.io/) cluster on [AWS](https://aws.amazon.com/) using [Terraform](https://www.terraform.io/). It follows the patterns laid out in the [Vault Reference Architecture](https://learn.hashicorp.com/vault/operations/ops-reference-architecture) and the [Vault Deployment Guide](https://www.vaultproject.io/guides/operations/deployment-guide.html).

## Contents

* A Terraform module to install Vault into AWS.
* A packer directory containing the packer code to build Vault and Consul AMIs
* The module can be used with the Packer built AMIs or user data to configure up to the standard listed in the [Deployment Guide](https://www.vaultproject.io/guides/operations/deployment-guide.html).

This module is specifically designed to deliver the [Reference Architecture](https://learn.hashicorp.com/vault/operations/ops-reference-architecture) and as such adheres to that pattern. This means that it has these specifics that are not configurable:
* A Vault cluster using TLS
* A Consul cluster using TLS
* The Vault cluster is backed by a Consul cluster for storage
* The Vault cluster is intended to be deployed into a _private_ subnet(s)
* The security groups attached to the Vault and Consul cluster members are non-configurable and allow for full functionality (see below)

The module has these specifics that are configurable:
* The Vault cluster can be set up as _n_ standalone instances or inside an ASG depending on your preference.
* The Vault cluster can be fronted by an _internal_ or _external_ ELB or not, depending on your preference.  
* The number of Vault nodes can be configured, though 3 is the default and recommended number
* The Consul cluster can be set up as _n_ standalone instances or inside an ASG depending on your preference.
* The number of Consul nodes can be configured though 5 is the default, 5 as per the recommended architecture.
* The recommended architecture suggests that the 3 Vault nodes be spread across 3 separate availability zones, but this module will take fewer than that.
* While this module manages the security groups to allow for the correct function of the cluster, it is possible to add further security groups to the instances if other connectivity is desired.
* The module can be set to install and configure Vault and Consul via user data or this can be turned off.
* The module contains packer scripts to build Vault and Consul AMIs as per the deployment guide if required so that you have the option of using user data, using the module AMI or building your own AMI.
* The Vault cluster can be set up to use AWS KMS key for auto unseal (something that is recommended if using an ASG)

## Versions
This module is written for Terraform 11.10 and has been tested with this version only.
This module has been tested with Ubuntu 18.04 and Centos 7.x OS
This has been tested with Vault 1.x
This has been tested with Consul 1.3.x, 1.4.x, and 1.5.x.

## Setup
This module is to deliver a Vault cluster on Linux with systemd on AWS and assumes you already have a VPC in place with subnets for public and private facing hosts as well as the security groups to allow communication between them for management.

## Usage
```hcl
module vault_cluster {

  # This source should be the tag for this module if pulling from git or the public terraform module registry
  source                 = "../terraform-aws-vault/vault-cluster"

  cluster_name       = "${var.cluster_name}"
  vault_ami_id       = "${var.vault_ami_id}"
  consul_ami_id      = "${var.consul_ami_id}"

  # Change the referenced module name here to match yours or to pull from an existing remote state store
  private_subnets    = "${module.vpc.private_subnets}"
  public_subnets     = "${module.vpc.public_subnets}"
  vpc_id             = "${module.vpc.vpc_id}"

  use_asg            = false
  use_elb            = false
  internal_elb       = false
  use_auto_unseal    = true
  availability_zones = "${var.availability_zones}"
  aws_region         = "${var.global_region}"
  vault_cluster_size = 3
  consul_cluster_size = 5
  use_userdata      = true

  # Use vault_binary if you want to supply the file from an S3 bucket, else use the version number to download it
  # vault_binary    = "vault.zip"
  vault_version     = "1.2.1"
  consul_version    = "1.4.5"
}
```
## Variables
### Required Input Variables
* cluster_name        - name of your cluster
* vault_ami_id        - The AMI id for the Vault cluster server instances. This can be the same as the consul_ami_id if you are using the user data install method.
* consul_ami_id       - The AMI id for the Consul cluster server instances
* instance_type       - The AWS instance type you wish for the Vault and Consul servers
* ssh_key_name        - The AWS key-pair name to use for the instances
* private_subnets     - a list of the private subnets the cluster will be installed to.
* public_subnets      - a list of the public subnets the ELB will be installed to.
* availability_zones  - The availability zones that the cluster will be installed in. This should match up with the private_subnets list so that there is at least 1 subnet in each AZ.
* vpc_id              - The AWS VPC id
* aws_region          - The region the Vault cluster will be deployed in

### Optional Input Variables
These are listed below with their defined defaults. If you wish to change the variable value then define it in the code block for the module. see the `variables.tf` file for descriptions.

#### Cluster behaviour
* use_asg (false)
* use_elb (false)
* use_userdata (false)
* use_auto_unseal (false)
* internal_elb (true)
* vault_cluster_size (3)
* consul_cluster_size (5)
* consul_cluster_tag (My_consul_cluster)
* vault_cluster_tag (My_vault_cluster)
* consul_storage_tag_key (CONSUL_STORAGE_CLUSTER_TAG)
* additional_sg_ids ([])

#### ASG Variables
* health_check_grace_period (300)
* wait_for_capacity_timeout (10m)
* enabled_metrics ([])
* termination_policies (Default)

#### ELB Variables
* cross_zone_load_balancing (true)
* idle_timeout (60)
* connection_draining (true)
* connection_draining_timeout (300)
* lb_port (8200)
* vault_api_port (8200)
* health_check_protocol (HTTPS)
* health_check_path (/v1/sys/health)
* health_check_interval (15)
* health_check_healthy_threshold (2)
* health_check_unhealthy_threshold (2)
* health_check_timeout (5)

#### Userdata Variables
* vault_binary ("")
* vault_version ("")
* consul_version ("")
* consul_binary ("")

#### KMS Variables
* kms_deletion_days (7)
* kms_key_rotate (false)

### Output Variables
* vault_cluster_instance_ids - The instance IDs for the Vault instances.
* vault_cluster_instance_ips - The instance IPs for the Vault instances.
* consul_cluster_instance_ids - The instance IDs for the Consul instances.
* consul_cluster_instance_ips - The instance IPs for the Consul instances.
* elb_dns - the DNS name for the internal ELB
* cluster_server_role - The role name for the IAM role assigned to the cluster instances for use with attaching policies.

## Infrastructure Options
This module will install Vault as `$var.vault_cluster_size` individual instances or as `$var.vault_cluster_size` instances inside an ASG
This behaviour is controlled by the use of a boolean variable `use_asg`
The default is false
```hcl
  /* This variable is a boolean that determines whether the Vault cluster is
  provisioned inside an ASG. */

  use_asg           = false
```
This module will install Vault with or without an _internal_ ELB/
This behaviour is controlled by the use of a boolean variable `use_elb`
The default is false
```hcl
  /* This variable is a boolean that determines whether the Vault cluster is
  provisioned behind an ELB */

  use_elb           = false
```
If an ELB is used then you have the option for this to be an internal (recommended) or external by use of the internal_elb variable.

```hcl
/* this variable is a boolean that determines if the ELB is internal or
 external. If use_elb is set to false then it will have no effect*/

internal_elb = false
```

## Use of awskms autounseal
This module will configure and deploy a AWS KMS key and set the cluster to use this for auto unsealing. This behaviour is controlled by the use of a boolean variable `use_auto_unseal` The default is false
```hcl
/* This variable controls the creation of a KMS key for use with awskms
seal operations */

use_auto_unseal   = false
```
## User Data Install

If the `use_userdata` variable is set to `false` then no post install user data configuration will take place and it is assumed that the cluster configuration will be done via some other method. This module also provides Packer scripts to perform this. See below *Packer Install*

If the `use_userdata` variable is set to `true` then the user data scripts will be used and the user data install files must be set up prior to deployment. The steps for doing this are below.

```hcl
  /* User Data. This sets up the configuration of the cluster.
  If use use_userdata variable is set to false then none of these need be
  configured as they will not be used and they are set to default variables in
  the module variables.tf.  */

  vault_binary        = "s3://my_install_bucket/vault.zip"
  consul_version      = "1.3.1"
  consul_cluster_size = 5
```
This user data install will install Vault and Consul binaries either from the S3 location or download them directly from the [hashicorp releases](https://releases.hashicorp.com/) page.
This behaviour is controlled by the use of the [vault|consul] version and bin variables.
```hcl
  # This will mean the install will look for the Vault binary in the S3 bucket
  vault_binary      = "s3://my_install_bucket/vault.zip"
  # This will mean the install will download the release from releases page
  vault_version  = "1.0.1"
  # This will mean the install will look for the Consul binary in the S3 bucket
  consul_bin     = "s3://my_install_bucket/consul.zip"
  # This will mean the install will download the release from releases page
  consul_version = "1.3.1"
```
You should use either the *binary* or the *version* for each application. If you put in both, the install  will only look in the S3 bucket.
You can have the behaviour different for each application if you wish.

## Packer Install
The packer directory contains 2 packer configurations - one to install the Vault nodes and one to install the Consul nodes. This will give you 2 AMIs that can be used in the module as:
```hcl
vault_ami_id           = "${var.vault_ami_id}"
consul_ami_id          = "${var.consul_ami_id}"
```
If you pre-build the AMIs via this method then you should also set the use_userdata variable to false so that the Vault and Consul installs are not overwritten.

```
use_userdata = false
```

## Final Configuration
If the cluster has been configured either by the user data or Packer method from this module then there is one final step that is required to complete the configuration as per the deployment guide. This final step cannot (and arguably should not) be completed at the Terraform deployment stage and so a directory called 'config' in the examples directory contains the scripts to perform this.

This directory contains configuration scripts which update the base Consul installation to meet more stringent security and operational requirements that are typically seen in production environments.

The vision for this section of the repository is to house the most popular tools for configuration management such as Ansible, Chef, Puppet and Salt. As a baseline that should work in most environments, Bash scripts are provided.
