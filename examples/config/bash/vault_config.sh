#!/bin/bash
#We should attempt to use the below strict mode:
#set -e -u -o pipefail
#
#######################################################################################################
# AUTHOR: Arctiq, Iain Gray, and James Anderton
# DATE: Mar 15 2019
# UPDATED: OCT 13 2019
# PURPOSE: # This script is used to do the final config of Vault as per the
#            deployment guide. The gcloud command must be installed and configured
#            with the Vault project as the default.
#
# REQUIREMENTS:
# Ensure the certificates are created and in the same directory as this script before running
#
# Ensure CONSUL and VAULT CLUSTER TAGS are set to match what was configured in your Terraform plan:
#
# The flags required to run this script are as follows:
# [-t CONSUL_CLUSTER_TAG] *unless manually setting CONSUL_IPS
# [-T VAULT_CLUSTER_TAG] *unless manually setting VAULT_IPS
# [-u SSH_USER]
# [-d CONSUL_DATA_CENTER]
# [-D CONSUL_DOMAIN]
# [-c CLOUD_PROVIDER]
# [-p GCP_Project] if applicable
#
# You can manually set the ip addresses of the consul and vault servers in the 2
# arrays CONSUL_IPS and VAULT_IPS OR Use Auto-Discovery
#
# the ips should be unquoted and separated by a space
# e.g.
# declare -a CONSUL_IPS=(10.0.0.3 10.0.1.45, 10.0.2.67)
# The CONSUL_IPS should contain only the consul servers not the agents on the
# vault servers
#
declare -a CONSUL_IPS=()
declare -a VAULT_IPS=()
#
#
####Auto-Discovery of cloud Servers:######
# If you are on AWS or GCP you can use the [-p CLOUD_PROVIDER] flag and pass either "aws" or "gce" and we will auto discover your instances via 
# the SDK for the cloud specified. If the host you are running this from has the IAM policy permissions to allow
# "ec2:DescribeInstances",
# "ec2:DescribeTags",
#  
# OR for Google, the IAM Permissions needed are XXX
#
## For AWS Hosts we run:
# declare -a VAULT_IPS=($(aws ec2 describe-instances --filters "Name=instance-state-name,Values=running" "Name=tag:Function,Values=vault_server" "Name=tag:VAULT_CLUSTER_TAG,Values=${vault_cluster_tag}" | jq -r .Reservations[].Instances[].PrivateIpAddress))
# declare -a CONSUL_IPS=($(aws ec2 describe-instances --filters "Name=instance-state-name,Values=running" "Name=tag:Function,Values=consul_server" "Name=tag:CONSUL_STORAGE_CLUSTER_TAG,Values=${consul_cluster_tag}" | jq -r .Reservations[].Instances[].PrivateIpAddress))
#
## For GCP Hosts we run:
#  declare -a CONSUL_IPS=$(gcloud compute instances list --project ${gcp_project} --filter="tags.items=${consul_cluster_tag}" --format=json | jq -r '.[].networkInterfaces | .[].networkIP')
#  declare -a VAULT_IPS=$(gcloud compute instances list --project ${gcp_project} --filter="tags.items=${vault_cluster_tag}" --format=json | jq -r '.[].networkInterfaces | .[].networkIP')
#
#
# When settting the SSH_USER variable, set it to the user that was used in the instance creation
# Defaults are :
# AmazonLinux == ec2-user
# Ubuntu == ubuntu
# Centos == centos
#
#
#######################################################################################################
#
#####  GLOBALS
#
# Consul certs and keys
# filename and location relative to the script
SERVER_CERT="server_cert.pem"
SERVER_KEY="server_key.pem"
CA_CERT="ca_cert.pem"

# Vault TLS keys
TLS_CRT="tls.crt"
TLS_KEY="tls.key"

# Consul version
# This should be set as MAJOR.MINOR but not the patch level
# e.g.
#  if you are running Consul 1.3.1 set CONSUL_VERSION to 1.3
#  if you are running Consul 1.4.5 set CONSUL_VERSION to 1.4
CONSUL_VERSION="" #This is set via flag -v

TMP_DIR="/tmp/vault_config"
CONSUL_PORT="7500"
CONSUL_SSL_PORT="7501"
VAULT_PORT="8200"
VAULT_CLUSTER_PORT="8201"

########### End Globals ###############################################################################

function log {
  local -r level="$1"
  local -r func="$2"
  local -r message="$3"
  local -r timestamp=$(date +"%Y-%m-%d %H:%M:%S")
  >&2 echo -e "${timestamp} [${level}] [${func}] ${message}"
}
################### End Function ######################################################################

function get_consul_version {
  local func="get_consul_version"
  local ip=$1
  local consul_ver
  log "INFO" ${func} "Finding version of downloaded consul"
  consul_ver=$(ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" ${SSH_USER}@${ip} sudo ${DEFAULT_CONSUL_PATH} -v | head -1 |cut -d' ' -f2|sed 's/^v//'|cut -d'.' -f1,2)
  echo ${consul_ver}
}
################### End Function ######################################################################

function generate_gossip_key {
  local func="generate_gossip_key"
  local ip="$1"
  local gossip_key
  log "INFO" ${func} "Generating the gossip encryption key on host."
  gossip_key=$(ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" ${SSH_USER}@${ip} sudo /usr/local/bin/consul keygen)
  echo $gossip_key
}
################### End Function ######################################################################

function add_gossip_key {
  local func="add_gossip_key"
  local ip="$1"
  local key="$2"
  log "INFO" ${func} "Adding the gossip encryption key on host ${ip}."
  ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no"  ${SSH_USER}@${ip} \
   "sudo sed -i 's/\#encrypt[[:space:]]\+=[[:space:]]\+\"{{ gossip-key }}\"/encrypt = \"${key}\"/' ${DEFAULT_CONSUL_CONFIG_PATH}/${DEFAULT_CONSUL_CONFIG}"
}
################### End Function ######################################################################

function uncomment_consul_hcl {
  local func="uncomment_consul_hcl"
  local ip="$1"
  log "INFO" ${func} "Uncommenting consul HCL ${ip}."
  ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no"  ${SSH_USER}@${ip} \
   "sudo sed -i  's/^#//g' ${DEFAULT_CONSUL_CONFIG_PATH}/${DEFAULT_CONSUL_CONFIG}"

  # Restarting Services to use new configs
  consul_state="$(ssh -o 'UserKnownHostsFile=/dev/null' -o 'StrictHostKeyChecking=no' ${SSH_USER}@${ip} sudo systemctl show --property=SubState consul-storage|cut -d'=' -f2)"
  if [ "${consul_state}" == "dead" ] || [ "${consul_state}" == "failed" ]; then
    ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no"  ${SSH_USER}@${ip} \
    "sudo systemctl start consul-storage.service"
  else
        ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no"  ${SSH_USER}@${ip} \
    "sudo systemctl stop consul-storage.service && sudo systemctl start consul-storage.service"
  fi

  # vault_state="$(ssh -o 'UserKnownHostsFile=/dev/null' -o 'StrictHostKeyChecking=no' ${SSH_USER}@${ip} sudo systemctl show --property=SubState vault|cut -d'=' -f2)"
  # if [ "${vault_state}" == "dead" ] || [ "${vault_state}" == "failed" ]; then
  #   ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no"  ${SSH_USER}@${ip} \
  #   "sudo systemctl start vault.service"
  # fi
  # ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no"  ${SSH_USER}@${ip} \
  # "sudo systemctl stop vault.service && sudo systemctl start vault.service"

}
################### End Function ######################################################################

function reset_consul_server_hcl {
  local func="reset_consul_hcl"
  local ip="$1"
  local ver=${CONSUL_VERSION}
  local version_test=""

  log "INFO" ${func} "Commenting out Certs, Encryption, and ACLs from consul HCL on server ${ip}."

# Set up the configs so they can be easily interpolated into the functions
######################################################
# Consul 1.3 or lower
######################################################
if [ -z CONSUL_SERVER_CONFIG_13 ];then
  rm -f CONSUL_SERVER_CONFIG_13
fi

cat << EOF > CONSUL_SERVER_CONFIG_13
datacenter        = "${CONSUL_DC}"
domain            = "${CONSUL_DOMAIN}"
data_dir          = "${DEFAULT_CONSUL_OPT}"
retry_join        = ["provider=${DEFAULT_CLOUD}  tag_key=CONSUL_STORAGE_CLUSTER_TAG  tag_value=${CONSUL_SERVER_TAG}"]
performance {
  raft_multiplier = 1
}

addresses {
  http  = "0.0.0.0"
  https = "0.0.0.0"
  dns   = "0.0.0.0"
}

ports {
  dns             = 7600
  http            = 7500
  https           = 7501
  serf_lan        = 7301
  serf_wan        = 7302
  server          = 7300
}
bootstrap_expect = ${#CONSUL_IPS[@]}

##encrypt                 = "{{ gossip-key }}"
#ca_file           = "${DEFAULT_CONSUL_CONFIG_PATH}/ca_cert.pem"
#cert_file         = "${DEFAULT_CONSUL_CONFIG_PATH}/server_cert.pem"
#key_file          = "${DEFAULT_CONSUL_CONFIG_PATH}/server_key.pem"
#verify_outgoing   = true
#verify_server_hostname  = true
#acl_datacenter =  "${CONSUL_DC}"
#acl_default_policy =  "deny"
#acl_down_policy =  "extend-cache"
##acl_agent_token = {{ acl_token }}

server = true
ui = true

EOF
######################################################
# Consul 1.4 or higher
######################################################
if [ -z CONSUL_SERVER_CONFIG_14 ];then
  rm -f CONSUL_SERVER_CONFIG_14
fi

cat << EOF > CONSUL_SERVER_CONFIG_14
datacenter              = "${CONSUL_DC}"
domain            = "${CONSUL_DOMAIN}"
data_dir                = "${DEFAULT_CONSUL_OPT}"
enable_script_checks    = false
disable_remote_exec     = true
retry_join              = ["provider=${DEFAULT_CLOUD}  tag_key=CONSUL_STORAGE_CLUSTER_TAG  tag_value=${CONSUL_SERVER_TAG}"]
performance {
  raft_multiplier = 1
}

addresses {
  http  = "0.0.0.0"
  https = "0.0.0.0"
  dns   = "0.0.0.0"
}

ports {
  dns         = 7600
  http        = 7500
  https       = 7501
  serf_lan    = 7301
  serf_wan    = 7302
  server      = 7300
}
bootstrap_expect = ${#CONSUL_IPS[@]}
server = true
ui = true
primary_datacenter      = "${CONSUL_DC}"

##encrypt                 = "{{ gossip-key }}"
#verify_incoming_rpc     = true
#verify_outgoing         = true
#verify_server_hostname  = true
#ca_file                 = "${DEFAULT_CONSUL_CONFIG_PATH}/ca_cert.pem"
#cert_file               = "${DEFAULT_CONSUL_CONFIG_PATH}/server_cert.pem"
#key_file                = "${DEFAULT_CONSUL_CONFIG_PATH}/server_key.pem"
#acl {
#  enabled                   = true,
#  default_policy            = "deny",
#  enable_token_persistence  = true
#}
EOF
######################################################

  ver=$(get_consul_version "${ip}")
  version_test=$(echo "${ver} < 1.4" | bc)
  log "DEBUG" ${func} "Found Consul Version ${ver} and it is ${version_test}."
  
  if [ $version_test -eq 0 ]; then
    # greater than 1.3
    scp -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no"  CONSUL_SERVER_CONFIG_14 ${SSH_USER}@${ip}:~/CONSUL_SERVER_CONFIG_14
    ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no"  ${SSH_USER}@${ip} \
    "sudo cp -rf ~/CONSUL_SERVER_CONFIG_14 ${DEFAULT_CONSUL_CONFIG_PATH}/${DEFAULT_CONSUL_CONFIG}"
  else
    scp -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" CONSUL_SERVER_CONFIG_13 ${SSH_USER}@${ip}:~/CONSUL_SERVER_CONFIG_13
    ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no"  ${SSH_USER}@${ip} \
    "sudo cp -rf ~/CONSUL_SERVER_CONFIG_13 ${DEFAULT_CONSUL_CONFIG_PATH}/${DEFAULT_CONSUL_CONFIG}"
  fi
 
  echo "Resetting Consul HCL File Complete"
}


function reset_vault_hcl {
  local func="reset_vault_hcl"
  local ip="$1"

  log "INFO" ${func} "Commenting out Certs, Encryption, and ACLs from Vault HCL on server ${ip}."
######################################################
# Vault Config
######################################################
if [ -z VAULT_CONFIG ];then
  rm -f VAULT_CONFIG
fi

cat << EOF > VAULT_CONFIG
listener "tcp" {
  #certs setup for vault
  tls_cert_file            = "${DEFAULT_VAULT_CONFIG_PATH}/tls.crt"
  tls_key_file             = "${DEFAULT_VAULT_CONFIG_PATH}/tls.key"
  address                  = "0.0.0.0:8200"
  tls_disable              = "false"
  tls_disable_client_certs = "true"
}
storage "consul" {
  address         = "127.0.0.1:7501"
  token           = {{ vault-token }}
  path            = "vault/"
  scheme          = "https"
  tls_ca_file     = "${DEFAULT_VAULT_CONFIG_PATH}/ca_cert.pem"
  tls_cert_file   = "${DEFAULT_VAULT_CONFIG_PATH}/server_cert.pem"
  tls_key_file    = "${DEFAULT_VAULT_CONFIG_PATH}/server_key.pem"
  tls_skip_verify = "true"
}
ui       = true
EOF
######################################################
  
  scp -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no"  VAULT_CONFIG ${SSH_USER}@${ip}:~/${VAULT_CONFIG}
  ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no"  ${SSH_USER}@${ip} \
  "sudo cp -rf ~/VAULT_CONFIG ${DEFAULT_VAULT_CONFIG_PATH}/${DEFAULT_VAULT_CONFIG}"

  echo "Resetting Vault HCL File Complete"

}
################### End Function ######################################################################

function reset_consul_agent_hcl {
  local func="reset_consul_hcl"
  local ip="$1"
  local ver=${CONSUL_VERSION}
  local version_test=""

  log "INFO" ${func} "Commenting out Certs, Encryption, and ACLs from consul HCL on server ${ip}."

# Set up the configs so they can be easily interpolated into the functions
######################################################
# Consul 1.3 or lower
######################################################
if [ -z CONSUL_AGENT_CONFIG_13 ];then
  rm -f CONSUL_AGENT_CONFIG_13
fi

cat << EOF > CONSUL_AGENT_CONFIG_13
datacenter        = "${CONSUL_DC}"
domain            = "${CONSUL_DOMAIN}"
data_dir          = "${DEFAULT_CONSUL_OPT}"
retry_join        = ["provider=${DEFAULT_CLOUD}  tag_key=CONSUL_STORAGE_CLUSTER_TAG  tag_value=${CONSUL_SERVER_TAG}"]
performance {
  raft_multiplier = 1
}

addresses {
  http  = "0.0.0.0"
  https = "0.0.0.0"
  dns   = "0.0.0.0"
}

ports {
  dns             = 7600
  http            = 7500
  https           = 7501
  serf_lan        = 7301
  serf_wan        = 7302
  server          = 7300
}

##encrypt                 = "{{ gossip-key }}"
#ca_file           = "${DEFAULT_CONSUL_CONFIG_PATH}/ca_cert.pem"
#cert_file         = "${DEFAULT_CONSUL_CONFIG_PATH}/server_cert.pem"
#key_file          = "${DEFAULT_CONSUL_CONFIG_PATH}/server_key.pem"
#verify_outgoing   = true
#verify_server_hostname  = true
#acl_datacenter =  "${CONSUL_DC}"
#acl_default_policy =  "deny"
#acl_down_policy =  "extend-cache"
##acl_agent_token = {{ acl_token }}

server = false
ui = false

EOF
######################################################
# Consul 1.4 or higher
######################################################
if [ -z CONSUL_AGENT_CONFIG_14 ];then
  rm -f CONSUL_AGENT_CONFIG_14
fi

cat << EOF > CONSUL_AGENT_CONFIG_14
datacenter              = "${CONSUL_DC}"
domain            = "${CONSUL_DOMAIN}"
data_dir                = "${DEFAULT_CONSUL_OPT}"
enable_script_checks    = false
disable_remote_exec     = true
retry_join              = ["provider=${DEFAULT_CLOUD}  tag_key=CONSUL_STORAGE_CLUSTER_TAG  tag_value=${CONSUL_SERVER_TAG}"]
performance {
  raft_multiplier = 1
}

addresses {
  http  = "0.0.0.0"
  https = "0.0.0.0"
  dns   = "0.0.0.0"
}

ports {
  dns         = 7600
  http        = 7500
  https       = 7501
  serf_lan    = 7301
  serf_wan    = 7302
  server      = 7300
}

##encrypt                 = "{{ gossip-key }}"
#verify_incoming_rpc     = true
#verify_outgoing         = true
#verify_server_hostname  = true
#ca_file                 = "${DEFAULT_CONSUL_CONFIG_PATH}/ca_cert.pem"
#cert_file               = "${DEFAULT_CONSUL_CONFIG_PATH}/server_cert.pem"
#key_file                = "${DEFAULT_CONSUL_CONFIG_PATH}/server_key.pem"
#acl {
#  enabled                   = true,
#  default_policy            = "deny",
#  enable_token_persistence  = true
#}
EOF
######################################################

  ver=$(get_consul_version "${ip}")
  version_test=$(echo "${ver} < 1.4" | bc)
  log "DEBUG" ${func} "Found Consul Version ${ver} and it is ${version_test}."
  
  if [ $version_test -eq 0 ]; then
    # greater than 1.3
    scp -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no"  CONSUL_AGENT_CONFIG_14 ${SSH_USER}@${ip}:~/CONSUL_AGENT_CONFIG_14
    ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no"  ${SSH_USER}@${ip} \
    "sudo cp -rf ~/CONSUL_AGENT_CONFIG_14 ${DEFAULT_CONSUL_CONFIG_PATH}/${DEFAULT_CONSUL_CONFIG}"  > /dev/null 2>&1
  else
    scp -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" CONSUL_AGENT_CONFIG_13 ${SSH_USER}@${ip}:~/CONSUL_AGENT_CONFIG_13
    ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no"  ${SSH_USER}@${ip} \
    "sudo cp -rf ~/CONSUL_AGENT_CONFIG_13 ${DEFAULT_CONSUL_CONFIG_PATH}/${DEFAULT_CONSUL_CONFIG}"  > /dev/null 2>&1
  fi
 
  echo "Resetting Consul HCL File Complete"
}


function reset_vault_hcl {
  local func="reset_vault_hcl"
  local ip="$1"

  log "INFO" ${func} "Commenting out Certs, Encryption, and ACLs from Vault HCL on server ${ip}."
######################################################
# Vault Config
######################################################
if [ -z VAULT_CONFIG ];then
  rm -f VAULT_CONFIG
fi

cat << EOF > VAULT_CONFIG
listener "tcp" {
  #certs setup for vault
  tls_cert_file            = "${DEFAULT_VAULT_CONFIG_PATH}/tls.crt"
  tls_key_file             = "${DEFAULT_VAULT_CONFIG_PATH}/tls.key"
  address                  = "0.0.0.0:8200"
  tls_disable              = "false"
  tls_disable_client_certs = "true"
}
storage "consul" {
  address         = "127.0.0.1:7501"
  token           = {{ vault-token }}
  path            = "vault/"
  scheme          = "https"
  tls_ca_file     = "${DEFAULT_VAULT_CONFIG_PATH}/ca_cert.pem"
  tls_cert_file   = "${DEFAULT_VAULT_CONFIG_PATH}/server_cert.pem"
  tls_key_file    = "${DEFAULT_VAULT_CONFIG_PATH}/server_key.pem"
  tls_skip_verify = "true"
}
ui       = true
EOF
######################################################
  
  scp -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no"  VAULT_CONFIG ${SSH_USER}@${ip}:~/${VAULT_CONFIG}
  ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no"  ${SSH_USER}@${ip} \
  "sudo cp -rf ~/VAULT_CONFIG ${DEFAULT_VAULT_CONFIG_PATH}/${DEFAULT_VAULT_CONFIG}"  > /dev/null 2>&1

  echo "Resetting Vault HCL File Complete"

}
################### End Function ######################################################################

function generate_master_token {
  local func="generate_master_token"
  local ip="$1"
  local ver=${CONSUL_VERSION}
  local mt=""
  local version_test=""
  log "INFO" ${func} "Generating the master ACL token."
  version_test=$(echo "${ver} < 1.4" | bc)
  if [ $version_test -eq 0 ]; then
    # greater than 1.3
    mt=$(curl -k -s --request PUT https://${ip}:${CONSUL_SSL_PORT}/v1/acl/bootstrap | jq -r '.SecretID')
  else
    mt=$(curl -k -s --request PUT https://${ip}:${CONSUL_SSL_PORT}/v1/acl/bootstrap | jq -r '.ID')
  fi
  log "DEBUG" "${func}" "MT = ${mt}"
  if [ -z "${mt}" ]; then
    log "FATAL" "${func}" "Generation of the master token on ${ip} failed. Exiting"
    exit 1
  fi
  echo ${mt}
}
################### End Function ######################################################################

function generate_agent_token {
  local func="generate_agent_token"
  local ip="$1"
  local ver=${CONSUL_VERSION}
  local version_test=""
  local at=""
  log "INFO" ${func} "Generating the agent ACL policy and token."
  version_test=$(echo "${ver} < 1.4" | bc)
  if [ $version_test -eq 0 ]; then
    # greater than 1.3
    pol_id=$(curl -k -s --request PUT --header "X-Consul-Token: $master_token" --data '{"Name": "agent-tokens", "Rules": "node_prefix \"\" { policy = \"write\" } service_prefix \"\" { policy = \"read\" } agent_prefix \"\" { policy = \"write\" } session_prefix \"\" { policy = \"write\" }"}' https://${ip}:${CONSUL_SSL_PORT}/v1/acl/policy)
    at=$(curl -k -s --request PUT --header "X-Consul-Token: $master_token" --data '{"Description": "Agent Token", "Policies": [{ "Name": "agent-tokens" }]}' https://${ip}:${CONSUL_SSL_PORT}/v1/acl/token | jq -r '.SecretID')
  else
    at=$(curl -k -s --request PUT --header "X-Consul-Token: ${master_token}" --data '{"Name": "Agent Token", "Type": "client", "Rules": "node \"\" { policy = \"write\" } service \"\" { policy = \"read\" }"}' https://${ip}:${CONSUL_SSL_PORT}/v1/acl/create | jq -r '.ID')
  fi
  log "DEBUG" "${func}" "AT = ${at}"
  echo ${at}
}
################### End Function ######################################################################

function generate_vault_token {
  local func="generate_vault_token"
  local ip="$1"
  local ver=${CONSUL_VERSION}
  local v_pid=""
  local vt=""
  local version_test=""
  log "INFO" ${func} "Generating the vault ACL policy."
  version_test=$(echo "${ver} < 1.4" | bc)
  if [ $version_test -eq 0 ]; then
    # greater than 1.3
    v_pid=$(curl -k -s --request PUT --header "X-Consul-Token: ${master_token}" --data '{"Name": "Vault-Token", "Rules": "key_prefix \"vault\" { policy = \"write\" } node_prefix \"\" { policy = \"write\" } service_prefix \"vault\" { policy = \"write\" } agent_prefix \"\" { policy = \"write\" } session_prefix \"\" { policy = \"write\" }"}' https://${ip}:${CONSUL_SSL_PORT}/v1/acl/policy)
    vt=$(curl -k -s --request PUT --header "X-Consul-Token: $master_token" --data '{"Description": "Vault-Token", "Policies": [{ "Name": "Vault-Token" }]}' https://${ip}:${CONSUL_SSL_PORT}/v1/acl/token | jq -r '.SecretID')
  else
    vt=$(curl -k -s --request PUT --header "X-Consul-Token: ${master_token}" --data '{"Name": "Vault Token", "Type": "client", "Rules": "node \"\" { policy = \"write\" } service \"vault\" { policy = \"write\" } agent \"\" { policy = \"write\" }  key \"vault\" { policy = \"write\" } session \"\" { policy = \"write\" } "}' https://${ip}:${CONSUL_SSL_PORT}/v1/acl/create | jq -r '.ID')
  fi
  echo ${vt}
}
################### End Function ######################################################################

function distribute_agent_token {
  local func="distribute_agent_token"
  local ip="$1"
  local ver=${CONSUL_VERSION}
  local version_test=""
  log "INFO" ${func} "Distributing the agent ACL token to ${ip}."
  version_test=$(echo "${ver} < 1.4" | bc)
  if [ $version_test -eq 0 ]; then
    # greater than 1.3
    curl -k -s --request PUT --header "X-Consul-Token: $master_token" --data '{"Token":"'$agent_token'"}' https://${ip}:${CONSUL_SSL_PORT}/v1/agent/token/agent
  else
    # there is no token persistence in COnsul < 1.4 so we have to put this in the config file
    ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no"  ${SSH_USER}@${ip} \
     "sudo sed -i  's/#acl_agent_token[[:space:]]\+=[[:space:]]\+{{ acl_token }}/acl_agent_token = \"${agent_token}\"/' ${DEFAULT_CONSUL_CONFIG_PATH}/${DEFAULT_CONSUL_CONFIG}"
  fi
}
################### End Function ######################################################################

function distribute_vault_token {
  local func="distribute_vault_token"
  local ip="$1"
  log "INFO" ${func} "Distributing the vault token to ${ip}."
  ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" ${SSH_USER}@${ip} "sudo sed -i 's:{{ vault-token }}:\"${vault_token}\":' ${DEFAULT_VAULT_CONFIG_PATH}/vault.hcl" > /dev/null 2>&1
}
################### End Function ######################################################################

function copy_consul_files {
  local func="copy_consul_files"
  local ip="$1"
  log "INFO" "${func}" "Copying install files to ${ip}"
  ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" ${SSH_USER}@${ip} "mkdir ${TMP_DIR}" > /dev/null 2>&1
  scp -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" ${SERVER_CERT} ${SERVER_KEY} ${CA_CERT} ${SSH_USER}@${ip}:${TMP_DIR} > /dev/null 2>&1
  # Need to temporarily open the permissions on the config dir to allow the chown to work
  ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" ${SSH_USER}@${ip} "sudo chmod 755 ${DEFAULT_CONSUL_CONFIG_PATH}" > /dev/null 2>&1
  ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" ${SSH_USER}@${ip} "sudo mv ${TMP_DIR}/${SERVER_CERT} ${TMP_DIR}/${SERVER_KEY} ${TMP_DIR}/${CA_CERT} ${DEFAULT_CONSUL_CONFIG_PATH}" > /dev/null 2>&1
  ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" ${SSH_USER}@${ip} "sudo chown ${DEFAULT_CONSUL_USER}:${DEFAULT_CONSUL_USER} ${DEFAULT_CONSUL_CONFIG_PATH}/*" > /dev/null 2>&1
  ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" ${SSH_USER}@${ip} "sudo chmod 750 ${DEFAULT_CONSUL_CONFIG_PATH}" > /dev/null 2>&1
}
################### End Function ######################################################################

function copy_vault_files {
  local func="copy_vault_files"
  local ip="$1"
  log "INFO" "${func}" "Copying install files to ${ip}"
  ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" ${SSH_USER}@${ip} \
    "mkdir ${TMP_DIR}" > /dev/null 2>&1
  scp -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" ${SERVER_CERT} ${SERVER_KEY} ${CA_CERT} ${TLS_CRT} ${TLS_KEY} ${SSH_USER}@${ip}:${TMP_DIR} > /dev/null 2>&1
  # Need to temporarily open the permissions on the config dir to allow the chown to work
  ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" ${SSH_USER}@${ip} "sudo chmod 755 ${DEFAULT_VAULT_CONFIG_PATH}" > /dev/null 2>&1
  ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" ${SSH_USER}@${ip} "sudo mv ${TMP_DIR}/${SERVER_CERT} ${TMP_DIR}/${SERVER_KEY} ${TMP_DIR}/${CA_CERT} ${DEFAULT_VAULT_CONFIG_PATH}" > /dev/null 2>&1
  ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" ${SSH_USER}@${ip} "sudo mv ${TMP_DIR}/${TLS_CRT} ${TMP_DIR}/${TLS_KEY} ${DEFAULT_VAULT_CONFIG_PATH}" > /dev/null 2>&1
  ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" ${SSH_USER}@${ip} "sudo chown vault:vault ${DEFAULT_VAULT_CONFIG_PATH}/*" > /dev/null 2>&1
  ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" ${SSH_USER}@${ip} "sudo chmod 750 ${DEFAULT_VAULT_CONFIG_PATH}" > /dev/null 2>&1
}
################### End Function ######################################################################

###############################################################################################################################
#
#  Function: Main
#
################################################################################################################################
function main {
  local func="main"
  if [ -z ${SSH_USER} ]; then
    log "ERROR" ${func} "The variable SSH_USER must be set"
    exit 1
  fi
  if [ ${#CONSUL_IPS[@]} -lt 1 ]; then
    log "ERROR" ${func} "The array CONSUL_IPS must be set"
    exit 1
  fi
  if [ ${#VAULT_IPS[@]} -lt 1 ]; then
    log "ERROR" ${func} "The array VAULT_IPS must be set"
    exit 1
  fi
  server_ips=("${CONSUL_IPS[@]}" "${VAULT_IPS[@]}")
  CONSUL_VERSION=$(get_consul_version "${CONSUL_IPS[0]}")

  log "INFO" ${func} "Configuring these Consul servers: ${server_ips[*]}"
  log "INFO" ${func} "Configuring these Vault servers: ${VAULT_IPS[*]}"

  log "INFO" ${func} "Making sure SSH is up"
  for ip in "${server_ips[@]}"; do
    ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" ${SSH_USER}@${ip} "echo 'SSH Test'" > /dev/null 2>&1
    while test $? -gt 0
    do
      sleep 5 # highly recommended - if it's in your local network, it can try an awful lot pretty quick...
      echo "Trying host ${ip} again..."
      ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" ${SSH_USER}@${ip} "echo 'SSH Test'" > /dev/null 2>&1
    done
  done
  log "INFO" ${func} "Making sure startup is complete"
  for ip in "${server_ips[@]}"; do
    ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" ${SSH_USER}@${ip} "while [ ! -f /var/lib/cloud/instance/boot-finished ]; do sleep 5; done" > /dev/null 2>&1
  done

# Copy the certs to Consul
  for ip in "${server_ips[@]}"; do
    copy_consul_files ${ip}
  done

  #Reset Config file by commenting all the cert stuff for consul
  echo "Starting Consul HCL Reset"

  for ip in "${CONSUL_IPS[@]}"; do
    reset_consul_server_hcl ${ip}
    echo "Completed Consul HCL Reset on ${ip}."
    ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" ${SSH_USER}@${ip} "sudo systemctl stop consul-storage && sudo systemctl start consul-storage" > /dev/null 2>&1
  done
  echo "Completed Consul HCL Reset on ${CONSUL_IPS[@]}."

  #Reset Config file by commenting all the cert stuff for vault
  echo "Starting VAULT HCL Reset"

  for ip in "${VAULT_IPS[@]}"; do
    reset_consul_agent_hcl ${ip}
    echo "Completed Consul Agent HCL Reset on ${ip}."
    reset_vault_hcl ${ip}
    echo "Completed Vault HCL Reset on ${ip}."
    ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" ${SSH_USER}@${ip} "sudo systemctl stop vault && sudo systemctl start vault" > /dev/null 2>&1
  done
  echo "Completed Vault HCL Reset on ${VAULT_IPS[@]}."

# Uncomment all the cert stuff for consul
  for ip in "${server_ips[@]}"; do
    uncomment_consul_hcl ${ip}
  done

  log "INFO" "${func}" "Ensure Consul service is running on ${CONSUL_IPS[0]}"
  ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" ${SSH_USER}@${CONSUL_IPS[0]} "sudo systemctl start consul-storage" > /dev/null 2>&1
  sleep 10
  consul_state="$(ssh -o 'UserKnownHostsFile=/dev/null' -o 'StrictHostKeyChecking=no' ${SSH_USER}@${CONSUL_IPS[0]} sudo systemctl show --property=SubState consul-storage|cut -d'=' -f2)"
  if [ "${consul_state}" == "dead" ] || [ "${consul_state}" == "failed" ]; then
    log "FATAL" "${func}" "${CONSUL_IPS[0]} failed to start. Exiting"
    exit 1
  fi
  unset consul_state
  master_token=$(generate_master_token ${CONSUL_IPS[0]})
  if [ -z "${master_token}" ]; then
    log "FATAL" "${func}" "Generation of the master token failed. Exiting"
    exit 1
  fi
  agent_token=$(generate_agent_token ${CONSUL_IPS[0]})
  vault_token=$(generate_vault_token ${CONSUL_IPS[0]})

  for ip in "${server_ips[@]}"; do
    distribute_agent_token ${ip}
  done
# Generate the gossip key
  gossip_key=$(generate_gossip_key "${CONSUL_IPS[0]}")
  echo "Gossip Encryption Key: ${gossip_key}"
  #
# Distribute gossip keys
  for ip in "${server_ips[@]}"; do
     add_gossip_key ${ip} ${gossip_key}
  done
  for ip in "${VAULT_IPS[@]}"; do
    distribute_vault_token ${ip}
  done

  for ip in "${VAULT_IPS[@]}"; do
    copy_vault_files ${ip}
  done

  declare -a dead_consul_servers

  log "INFO" "${func}" "Re-starting the Consul servers"
  for ip in "${server_ips[@]}"; do
    log "INFO" "${func}" "Re-starting the Consul server ${ip}"
    ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" ${SSH_USER}@${ip} "sudo systemctl restart consul-storage" > /dev/null 2>&1
    sleep 5
    consul_state="$(ssh -o 'UserKnownHostsFile=/dev/null' -o 'StrictHostKeyChecking=no' ${SSH_USER}@${CONSUL_IPS[0]} sudo systemctl show --property=SubState consul-storage|cut -d'=' -f2)"
    if [ "${consul_state}" == "dead" ] || [ "${consul_state}" == "failed" ]; then
      log "ERROR" "${func}" "Consul server ${ip} failed to start"
      dead_consul_servers+=("${ip}")
    fi
    if [ ${#dead_consul_servers[@]} -gt 0 ]; then
      log "FATAL" "${func}" "${#dead_consul_servers[@]} of ${#CONSUL_IPS[@]} failed to start. Exiting"
      exit 1
    fi
  done


  declare -a dead_vault_servers

  log "INFO" "${func}" "Starting the Vault servers"
  for ip in "${VAULT_IPS[@]}"; do
    log "INFO" "${func}" "Starting the Vault server ${ip}"
    ssh -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" ${SSH_USER}@${ip} "sudo systemctl start vault" > /dev/null 2>&1
    sleep 5
    vault_state="$(ssh -o 'UserKnownHostsFile=/dev/null' -o 'StrictHostKeyChecking=no' ${SSH_USER}@${VAULT_IPS[0]} sudo systemctl show --property=SubState vault|cut -d'=' -f2)"
    if [ "${vault_state}" == "dead" ] || [ "${vault_state}" == "failed" ]; then
      log "ERROR" "${func}" "Vault server ${ip} failed to start"
      dead_vault_servers+=("${ip}")
    fi
    if [ ${#dead_vault_servers[@]} -gt 0 ]; then
      log "FATAL" "${func}" "${#dead_vault_servers[@]} of ${#VAULT_IPS[@]} failed to start. Exiting"
      exit 1
    fi
  done

  echo "Gossip Encryption Key: ${gossip_key}"
  echo "Master ACL token: ${master_token}"
  echo "Agent ACL token: ${agent_token}"
  echo "Vault ACL token: ${vault_token}"
}
############# End Main ###############################################################################################################


################################################################################################################
#
#  Get input from CLI Flags
#
################################################################################################################

readonly DEFAULT_CONSUL_USER="consul-storage"
readonly DEFAULT_CONSUL_CONFIG_PATH="/etc/consul-storage.d"
readonly DEFAULT_CONSUL_OPT="/opt/consul-storage/"
readonly DEFAULT_CONSUL_CONFIG="consul.hcl"
readonly DEFAULT_CONSUL_SERVICE="/etc/systemd/system/consul-storage.service"
readonly DEFAULT_CONSUL_SERVICE_NAME="consul-storage"
readonly DEFAULT_CONSUL_PATH="/usr/local/bin/consul"

readonly DEFAULT_VAULT_USER="vault"
readonly DEFAULT_VAULT_CONFIG_PATH="/etc/vault.d"
readonly DEFAULT_VAULT_OPT="/opt/vault/"
readonly DEFAULT_VAULT_CONFIG="vault.hcl"
readonly DEFAULT_VAULT_SERVICE="/etc/systemd/system/vault.service"
readonly DEFAULT_VAULT_SERVICE_NAME="vault"
readonly DEFAULT_VAULT_PATH="/usr/local/bin/vault"

if (($# == 0)); then
      echo -e "script usage: $(basename $0) [-t CONSUL_CLUSTER_TAG] [-T VAULT_CLUSTER_TAG] [-v CONSUL_VERSION] [-V VAULT_VERSTION] " \
      "[-u SSH_USER] [-d CONSUL_DOMAIN] [-D CONSUL_DC] [-p GCP_PROJECT] [-c CLOUD_PROVIDER] \n"\
      "The following flags are required: [tTudDc]" >&2

      exit 2
fi

while getopts 't:T:v:V:u:d:D:c:Rp:h' OPTION; do
  case "$OPTION" in
    t)
      export CONSUL_SERVER_TAG="$OPTARG"

      if [ -z "$CONSUL_SERVER_TAG" ];then
        export CONSUL_SERVER_TAG="CONSUL_STORAGE_CLUSTER_TAG"
      fi

      echo "CONSUL_SERVER_TAG is $OPTARG"
      ;;

    T)
      export VAULT_SERVER_TAG="$OPTARG"

      if [ -z "$VAULT_SERVER_TAG" ];then
        export VAULT_SERVER_TAG="VAULT_CLUSTER_TAG"
      fi

      echo "VAULT_SERVER_TAG is $OPTARG"
      ;;

    v)
      export CONSUL_VERSION="$OPTARG"
      
      echo "CONSUL_VERSION is $OPTARG"
      ;;

    V)
      export VAULT_VERSION="$OPTARG"
      
      echo "VAULT_VERSION is $OPTARG"
      ;;

    u)
      export SSH_USER="$OPTARG"

      #if SSH_USER is empty, try the current user
      if [ ! -z "$SSH_USER" ];then
        echo "Setting SSH_USER to default current user. If this is not what you meant to do, please use the -u flag"
        export SSH_USER=`whoami`
      fi

      echo "The ssh username provided is $OPTARG"
      ;;
    
    d)
      export CONSUL_DOMAIN="$OPTARG"

      if [ ! -z "$CONSUL_DOMAIN" ]; then
        export CONSUL_DOMAIN="storage"
      fi

      echo "CONSUL_DOMAIN is $OPTARG"
      ;;

    D)
      export CONSUL_DC="$OPTARG"

      if [ ! -z "$CONSUL_DC" ];then
        export CONSUL_DC="vault"
      fi

      echo "CONSUL_DC is $OPTARG"
      ;;

    p)
      export GCP_PROJECT="$OPTARG"
      echo "The Google Cloud Project provided is $OPTARG"
      ;;
   
    c)
      export DEFAULT_CLOUD="$OPTARG"
      echo "The Cloud provider is $OPTARG"

      if [[ $DEFAULT_CLOUD == "aws" ]];then
      ## For AWS Hosts:
        declare -a VAULT_IPS=($(aws ec2 describe-instances --filters "Name=instance-state-name,Values=running" "Name=tag:Function,Values=vault_server" "Name=tag:VAULT_CLUSTER_TAG,Values=${VAULT_SERVER_TAG}" | jq -r .Reservations[].Instances[].PrivateIpAddress))
        declare -a CONSUL_IPS=($(aws ec2 describe-instances --filters "Name=instance-state-name,Values=running" "Name=tag:Function,Values=consul_server" "Name=tag:CONSUL_STORAGE_CLUSTER_TAG,Values=${CONSUL_SERVER_TAG}" | jq -r .Reservations[].Instances[].PrivateIpAddress))

        #declare -a VAULT_IPS=($(aws ec2 describe-instances --filters "Name=instance-state-name,Values=running,Name=tag:Function,Values=vault_server" | jq -r .Reservations[].Instances[].PrivateIpAddress))
        #declare -a CONSUL_IPS=($(aws ec2 describe-instances --filters "Name=instance-state-name,Values=running,Name=tag:Function,Values=consul_server" | jq -r .Reservations[].Instances[].PrivateIpAddress))

      elif [[ $DEFAULT_CLOUD == "gce" ]];then
      # On GCP, if the host you are running this from has a service account with compute.read, uncomment the below:
      ## For GCP Hosts:
         declare -a CONSUL_IPS=($(gcloud compute instances list --project ${GCP_PROJECT} --filter="tags.items=${CONSUL_SERVER_TAG}" --format=json | jq -r '.[].networkInterfaces | .[].networkIP'))
         declare -a VAULT_IPS=($(gcloud compute instances list --project ${GCP_PROJECT} --filter="tags.items=${VAULT_SERVER_TAG}" --format=json | jq -r '.[].networkInterfaces | .[].networkIP'))
      else
        echo "Please choose either [ aws OR gce ]"
      
      fi
      ;;

    R)
      # Uncomment all the cert stuff for consul
      echo "Starting Consul HCL Reset"

      server_ips=("${CONSUL_IPS[@]}" "${VAULT_IPS[@]}")
      for ip in "${server_ips[@]}"; do
        echo "Completed Consul HCL Reset on ${ip}."
        reset_consul_hcl ${ip}
      done

      echo "Completed Consul HCL Reset on ${server_ips[@]}."
      exit 0
      ;;      

    h)
      echo -e "script usage: $(basename $0) [-t CONSUL_SERVER_TAG] [-T VAULT_SERVER_TAG] [-v CONSUL_VERSION] [-V VAULT_VERSTION] " \
      "[-u SSH_USER] [-d CONSUL_DOMAIN] [-D CONSUL_DC] [-p GCP_PROJECT] [-c CLOUD_PROVIDER] \n"\
      "The following flags are required: [t:T:u:d:D:c:]" >&2

      exit 1
      ;;

    \?)
        echo "Invalid option: -$OPTARG" >&2
        exit 2;;
    :)
        echo "Option -$OPTARG requires an argument" >&2
        exit 2;;
  esac
done
shift "$(($OPTIND -1))"

########## End GetOpts ################################################################################################################

##### Starting Main Function #####
main
