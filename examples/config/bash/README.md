# Configuration Management with Bash

## Final Configuration
If the cluster has been configured either by the startup-script or Packer method from this module then there is one final step that is required to complete the configuration as per the deployment guide. This final step cannot (and arguably should not) be completed at the Terraform deployment stage and so a helper script is available here: `examples/config/bash/vault_config.sh`

This script performs the following functions:

* Generate an ACL master token on one Consul server (ACL bootstrap).
* Generate the agent ACL policy on one Consul server.
* Generate an agent ACL token on one Consul server.
* Add that agent ACL token on all Consul servers.
* Generate a Vault ACL token in Consul.
* Deploys TLS keys and certs to all Consul servers.
* Generate and distribute a Gossip encryption key for Consul.
* Deploys TLS keys and certs to Vault servers.
* Starts all services with the new certificates and keys.

For ease of use the Consul master token, agent token, vault token and gossip key are output by the script and should be saved (possibly as a Vault static secret) if this may be required again.

It is arguable whether this final step should be included in any sort of deployment as this is really the domain of configuration management, however it is included here for completeness to finalise the Consul install so that it fully replicates the deployment guide.

## Applying the Final Configuration

The following commands should be from a control machine with VPN or direct access on the same subnet as the Vault and Consul hosts.

#### TLS Keys
You will need to create a root certificate and a wildcard server cert and key for all Consul and Vault servers. This can be done via your normal TLS cert method or you can create self signed ones like so:

You will need version 1.4.1 or higher of the Consul binary installed locally or on the system running the configuration steps to generate the certificates and keys.

```shell
export aws_region="<YOUR_AWS_REGION>"
consul tls ca create
consul tls cert create -server \
  -additional-dnsname=*."$aws_region".compute.internal \
  -additional-dnsname=*.vault \
  -additional-dnsname=*.vault.storage \
  -additional-dnsname=*.vault-storage \
  -additional-dnsname=*.storage \
  -additional-dnsname=*.node.storage \
  -additional-dnsname=*.service.storage \
  -additional-dnsname=*.node.vault.storage \
  -additional-dnsname=*.service.vault.storage
consul tls cert create -server \
  -additional-dnsname=vault.example.com \
  -additional-dnsname=127.0.0.1 \
  -additional-dnsname-localhost

cp consul-agent-ca.pem ca_cert.pem
cp dc1-server-consul-0-key.pem server_key.pem
cp dc1-server-consul-0.pem server_cert.pem
cp dc1-server-consul-1-key.pem tls.key
cp dc1-server-consul-1.pem tls.crt
```
Ensure the generated keys are in the same directory as the `vault_config.sh` script.

#### Server IPs
If the host you are running this from has the aws cli tools installed and the IAM policy permissions to allow:
* "ec2:DescribeInstances"
* "ec2:DescribeTags"

then you can simply ue the -t and -T flags for auto-discovery and you do not need to supply the consul and vault server IPs.

Otherwise you should add the ip addresses of the consul **servers** to:
`CONSUL_IPS`
and the ip addresses of the vault servers to:
`VAULT_IPS`

#### Consul version
This script has been tested to install Consul version 1.3.x and above. There are some significant differences in the setup of the ACL system in Consul between 1.3.x and 1.4.x and this script takes this into account.
The script will attempt to auto-discover the version running, but you may set this by using the -v flag set the `CONSUL_VERSION` variable if needed for troublshooting.
This should be set as MAJOR.MINOR but not the patch level
e.g.
* if you are running Consul 1.3.1 set CONSUL_VERSION to 1.3
* if you are running Consul 1.4.5 set CONSUL_VERSION to 1.4

#### Other
Ensure the following variable match what was configured in your Terraform plan:

`CONSUL_CLUSTER_TAG`
`VAULT_CLUSTER_TAG`

Also you should set the `SSH_USER` variable to the user that was used in the instance creation
Defaults are :
* AmazonLinux == ec2-user
* Ubuntu == ubuntu
* Centos == centos

To apply the changes described above to your Vault cluster run the following command in this directory

```shell
chmod 700 vault_config.sh
./vault_config.sh -t <consul_cluster_tag> -T <vault_cluster_tag> -u <ssh_username> -d <consul_datacenter> -D <consul_domain> -c aws

```
