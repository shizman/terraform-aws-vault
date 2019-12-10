# Packer Scripts

There are 2 packer configs in this directory
* vault_install.json - A packer script to install Vault with Consul client.
* consul_install.json - A packer script to install Consul server

All inputs are variables and are explained here:

* "vault_binary": The name of the Vault binary. This is if you are installing from a binary rather than by downloading. Thsi must be a s3 address e.g. s3://bucket/file
* "consul_binary": The name of the Consul binary. This is if you are installing from a binary rather than by downloading. Thsi must be a s3 address e.g. s3://bucket/file
"vault_version": The version of Vault you want installed. This is if you are installing from download. This should be in the format of the Vault binary on the [releases page](https://releases.hashicorp.com/vault/)
* "consul_version": The version of Consul you want installed.  This is if you are installing from download. This should be in the format of the Consul binary on the [releases page](https://releases.hashicorp.com/consul/)
* "source_ami": The AWS AMI_ID to use as a base. This script has been tested on Centos 7 and Ubuntu 18.04
* "os_version_tag": The tag for the OS
* "ssh_user": The ssh user packer should use. This is "ubuntu" or "centos"
* "aws_region": The region to build in
* "inst_type": Instance type to use for the build
* "inst_profile": The instance profile name that Packer can use. This can alternatively be replaced with aws key and secret or env vars as per: https://www.packer.io/docs/builders/amazon.html#authentication
* "consul_cluster_tag": The Consul cluster tag value for Consul cluster joining
* "consul_cluster_size": The number of Consul servers expected in the cluster.

The packer install references 1 of 2 install scripts:
* install-consul-packer.sh - the script used to create a consul server machine
* install-vault-packer.sh - the script used to install a vault server with a consul agent in client mode.

## Usage
To run this:
```
packer build vault_install.json
packer build consul_install.json
```
The 2 amis created can be used in the vault module by the 2 variables:
`vault_ami_id`
`consul_ami_id`
