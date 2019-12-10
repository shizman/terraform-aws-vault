#!/bin/bash

# operating systems tested on:
#
# 1. Ubuntu 18.04
# https://aws.amazon.com/marketplace/pp/B07CQ33QKV
# 1. Centos 7
# https://aws.amazon.com/marketplace/pp/B00O7WM7QW

readonly DEFAULT_PROVIDER="aws"
readonly DEFAULT_CONSUL_INSTALL_PATH="/usr/local/bin/consul"
readonly DEFAULT_CONSUL_USER="consul-storage"
readonly DEFAULT_CONSUL_PATH="/etc/consul-storage.d"
readonly DEFAULT_CONSUL_OPT="/opt/consul-storage"
readonly DEFAULT_CONSUL_CONFIG="consul.hcl"
readonly DEFAULT_CONSUL_SERVICE="/etc/systemd/system/consul-storage.service"
readonly DEFAULT_CONSUL_SERVICE_NAME="consul-storage"
readonly CONSUL_DC="vault-storage"

readonly SCRIPT_DIR="$(cd "$(dirname "$${BASH_SOURCE[0]}")" && pwd)"
readonly TMP_DIR="/tmp/install"
readonly SCRIPT_NAME="$(basename "$0")"

# Variables interpolated via terraform template resource.
readonly USE_USERDATA=${use_userdata}
readonly CONSUL_VERSION=${consul_version}
readonly CONSUL_BINARY=${consul_binary}
readonly CONSUL_CLUSTER_SIZE=${consul_cluster_size}
readonly CONSUL_CLUSTER_TAG=${consul_cluster_tag}

# Set up the configs so they can be easily interpolated into the functions
######################################################
# Consul 1.3 or lower
######################################################
read -r -d '' CONSUL_CONFIG_13 << EOF
datacenter        = "$${CONSUL_DC}"
data_dir          = "$${DEFAULT_CONSUL_OPT}"
retry_join        = ["provider=$${DEFAULT_PROVIDER}  tag_key=CONSUL_STORAGE_CLUSTER_TAG  tag_value=$${CONSUL_CLUSTER_TAG}"]
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
bootstrap_expect = $${CONSUL_CLUSTER_SIZE}

##encrypt                 = "{{ gossip-key }}"
#ca_file           = "$${DEFAULT_CONSUL_PATH}/ca_cert.pem"
#cert_file         = "$${DEFAULT_CONSUL_PATH}/server_cert.pem"
#key_file          = "$${DEFAULT_CONSUL_PATH}/server_key.pem"
#verify_outgoing   = true
#verify_server_hostname  = true
#acl_datacenter =  "$${CONSUL_DC}"
#acl_default_policy =  "deny"
#acl_down_policy =  "extend-cache"
##acl_agent_token = {{ acl_token }}

server = true
ui = true

EOF
######################################################
# Consul 1.4 or higher
######################################################
read -r -d '' CONSUL_CONFIG_14 << EOF
datacenter              = "$${CONSUL_DC}"
data_dir                = "$${DEFAULT_CONSUL_OPT}"
enable_script_checks    = false
disable_remote_exec     = true
retry_join              = ["provider=$${DEFAULT_PROVIDER}  tag_key=CONSUL_STORAGE_CLUSTER_TAG  tag_value=$${CONSUL_CLUSTER_TAG}"]
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
bootstrap_expect = $${CONSUL_CLUSTER_SIZE}
server = true
ui = true
primary_datacenter      = "$${CONSUL_DC}"

##encrypt                 = "{{ gossip-key }}"
#verify_incoming_rpc     = true
#verify_outgoing         = true
#verify_server_hostname  = true
#ca_file                 = "$${DEFAULT_CONSUL_PATH}/ca_cert.pem"
#cert_file               = "$${DEFAULT_CONSUL_PATH}/server_cert.pem"
#key_file                = "$${DEFAULT_CONSUL_PATH}/server_key.pem"
#acl {
#  enabled                   = true,
#  default_policy            = "deny",
#  enable_token_persistence  = true
}
EOF
######################################################

function log {
  local -r level="$1"
  local -r func="$2"
  local -r message="$3"
  local -r timestamp=$(date +"%Y-%m-%d %H:%M:%S")
  >&2 echo -e "$${timestamp} [$${level}] [$${SCRIPT_NAME}:$${func}] $${message}"
}

function assert_not_empty {
  local func="assert_not_empty"
  local -r arg_name="$1"
  local -r arg_value="$2"

  if [[ -z "$${arg_value}" ]]; then
    log "ERROR" $${func} "The value for '$${arg_name}' cannot be empty"
    exit 1
  fi
}

function has_yum {
  [[ -n "$(command -v yum)" ]]
}

function has_apt_get {
  [[ -n "$(command -v apt-get)" ]]
}

function install_dependencies {
  local func="install_dependencies"
  log "INFO" $${func} "Installing dependencies"

  if has_apt_get; then
    sudo add-apt-repository multiverse
    sudo add-apt-repository universe
    sudo apt-get update -y
    sudo apt-get install -y jq
    sudo apt-get install -y curl
    sudo apt-get install -y unzip
    sudo apt-get install -y awscli
    # sudo DEBIAN_FRONTEND=noninteractive apt-get -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" upgrade
  elif has_yum; then
    # sudo yum update -y
    sudo yum install -y unzip jq curl
    sudo yum install -y epel-release
    sudo yum install -y python-pip
    sudo pip install awscli
    sudo yum install -y perl-Digest-SHA
  else
    log "ERROR" $${func} "Could not find apt-get or yum. Cannot install dependencies on this OS."
    exit 1
  fi
}

function user_exists {
  local -r username="$1"
  id "$${username}" >/dev/null 2>&1
}

function create_user {
  local func="create_user"
  local -r username="$1"
  log "INFO" $${func} "User $${username} Creating"
  if $(user_exists "$${username}"); then
    log "INFO" $${func} "User $${username} already exists. Will not create again."
  else
    if [ $${username} = "vault" ]; then
      log "INFO" $${func} "Creating user named $${username}"
      sudo useradd --system --home $${DEFAULT_VAULT_PATH} --shell /bin/false $${username}
    fi
    if [ $${username} = "consul-storage" ]; then
      log "INFO" $${func} "Creating user named $${username}"
      sudo useradd --system --home $${DEFAULT_CONSUL_PATH} --shell /bin/false $${username}
    fi
  fi
}

function get_consul_version {
  local func="get_consul_version"
  log "INFO" $${func} "finding version of downloaded consul"
  c_v=$($${DEFAULT_CONSUL_INSTALL_PATH} -v | head -1 |cut -d' ' -f2|sed 's/^v//'|cut -d'.' -f1,2)
  my_v=$(echo "$${c_v} < 1.4" | bc)
  echo $${my_v}
  log "INFO" $${func} "CV = $${c_v}, V = $${my_v}"
}

function create_install_paths {
  local func="create_install_paths"
  local -r path="$1"
  local -r username="$2"
  local -r config="$3"
  local -r opt="$4"
  local -r tag_val="$5"
  local -r software="$6"
  local -r consul_ver="$7"

  log "INFO" $${func} "path = $${path} username=$${username} config = $${config} opt = $${opt}  tag_val = $${tag_val}"

  log "INFO" $${func} "Creating install dirs for $${software} at $${path}"
  if [[ ! -d "$${path}" ]]; then
    sudo mkdir -p "$${path}"
  fi
  sudo chmod 750 "$${path}"
  sudo chown "$${username}":"$${username}" "$${path}"
  sudo mkdir -p "$${opt}"
  sudo chmod 750 "$${opt}"
  sudo chown "$${username}":"$${username}" "$${opt}"

  if [ "$${software}" == "consul" ]; then
    if [ $${consul_ver} -eq 0 ]; then
      # Consul version 1.4 or greater
      echo "$${CONSUL_CONFIG_14}" > $${TMP_DIR}/outy
    else
      # Consul version 1.3 or less
      echo "$${CONSUL_CONFIG_13}" > $${TMP_DIR}/outy
    fi
  elif [ "$${software}" == "vault" ]; then
    echo "$${VAULT_CONFIG}" > $${TMP_DIR}/outy
  else
    log "ERROR" $${func} "software type unknown -- $${software}"
  fi

  sudo cp $${TMP_DIR}/outy $${path}/$${config}
  sudo chown "$${username}":"$${username}" $${path}/$${config}
  sudo chmod 640 $${path}/$${config}
}

function get_binary {
  # if there is no version then we are going to get binary from S3
  # else we download from Consul site. This is set by type variable of 1 or 0
  # if type == 1 then we get bin from S3
  # else we get bin from download
  # The instance needs access to the S3 bucket either as a public bucket or better
  # as a private bucket with IAM role permissions

  local func="get_binary"
  local -r bin="$1"
  local -r type="$2"
  local -r software="$3"
  local -r zip="$4"
  # get from download
  if [[ $${type} != 1 ]]; then
    ver="$${bin}"
    assert_not_empty "--version" $${ver}
    log "INFO" $${func} "Copying $${software} version $${ver} binary to local"
    cd $${TMP_DIR}
    curl -O https://releases.hashicorp.com/$${software}/$${ver}/$${software}_$${ver}_linux_amd64.zip
    curl -Os https://releases.hashicorp.com/$${software}/$${ver}/$${software}_$${ver}_SHA256SUMS
    curl -Os https://releases.hashicorp.com/$${software}/$${ver}/$${software}_$${ver}_SHA256SUMS.sig
    sha256sum -c $${software}_$${ver}_SHA256SUMS 2> /dev/null | grep $${software}_$${ver}_linux_amd64.zip | grep OK
    ex_c=$?
    if [[ $${ex_c} -ne 0 ]]; then
      log "ERROR" $${func} "The download of the $${software} binary failed"
      exit
    else
      log "INFO" $${func} "The download of $${software} binary successful"
    fi
    unzip -tqq $${TMP_DIR}/$${zip}
    if [[ $? -ne 0 ]]; then
      log "ERROR" $${func} "Downloaded $${software} binary is not a zip file"
      exit
    fi
  else
    log "INFO" $${func} "Copying Vault binary from $${bin} to local"
    aws s3 cp "$${bin}" "$${TMP_DIR}/$${zip}"
    ex_c=$?
    log "INFO" $${func} "aws copy exit code == $${ex_c}"
    if [[ $${ex_c} -ne 0 ]]; then
      log "ERROR" $${func} "The copy of the $${software} binary from $${bin} failed"
      exit
    else
      log "INFO" $${func} "Copy of $${software} binary successful"
    fi
    unzip -tqq $${TMP_DIR}/$${zip}
    if [[ $? -ne 0 ]]; then
      log "ERROR" $${func} "Supplied $${software} binary is not a zip file"
      exit
    fi
  fi
}

function install_binary {
  local func="install_binary"
  local -r loc="$1"
  local -r tmp="$2"
  local -r zip="$3"
  local -r software="$4"
  log "INFO" $${func} "LOC = $${loc}, TMP = $${tmp}, ZIP = $${zip} SOFTWARE = $${software}"

  if [ $${software} == "consul" ]; then
    local -r user="$${DEFAULT_CONSUL_USER}"
  fi
  if [ $${software} == "vault" ]; then
    local -r user="$${DEFAULT_VAULT_USER}"
  fi

  log "INFO" $${func} "Installing $${software}"
  cd $${tmp} && unzip -q $${zip}
  sudo chmod 750 "$${software}"
  sudo chown "$${user}":root "$${software}"
  sudo mv "$${software}" $${loc}
  if [ $${software} == "vault" ]; then
    sudo setcap cap_ipc_lock=+ep "$${loc}"
  fi
}

function create_service {
  local func="create_service"
  local -r service="$1"
  local -r software="$2"

  log "INFO" $${func} "Creating $${software} service"
  if [ "$${software}" == "consul" ]; then
    cat <<EOF > /tmp/outy
[Unit]
Description="HashiCorp Consul - A service mesh solution"
Documentation=https://www.consul.io/
Requires=network-online.target
After=network-online.target
ConditionFileNotEmpty=$${DEFAULT_CONSUL_PATH}/$${DEFAULT_CONSUL_CONFIG}

[Service]
User=$${DEFAULT_CONSUL_USER}
Group=$${DEFAULT_CONSUL_USER}
ExecStart=$${DEFAULT_CONSUL_INSTALL_PATH} agent -config-file=$${DEFAULT_CONSUL_PATH}/$${DEFAULT_CONSUL_CONFIG}
ExecReload=$${DEFAULT_CONSUL_INSTALL_PATH} reload
KillMode=process
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
  fi

  sudo cp /tmp/outy $${service}
  sudo systemctl enable $${service}
}

function main {
  local func="main"
  if [ -e $${TMP_DIR} ]; then
    rm -rf "$${TMP_DIR}"
  fi
  mkdir "$${TMP_DIR}"

  log "INFO" "$${func}" "Starting Consul install"
  install_dependencies
  create_user "$${DEFAULT_CONSUL_USER}"
  # if there is no version then we are going to get binary from S3
  # else we download from Vault site
  if [ -z $${CONSUL_BINARY} ]; then
    CONSUL_TMP_ZIP="consul_$${CONSUL_VERSION}_linux_amd64.zip"
    get_binary "$${CONSUL_VERSION}" 0 "consul" "$${CONSUL_TMP_ZIP}"
  else
    if [[ $${CONSUL_BINARY} =~ ^s3:// ]]; then
      CONSUL_TMP_ZIP="consul.zip"
      get_binary "$${CONSUL_BINARY}" 1 "consul" "$${CONSUL_TMP_ZIP}"
    else
      log "ERROR" "$${func}" "Consul binary is $${CONSUL_BINARY} but should be an s3 url"
    fi
  fi

  install_binary "$${DEFAULT_CONSUL_INSTALL_PATH}" "$${TMP_DIR}" "$${CONSUL_TMP_ZIP}" consul
  consul_dl_ver=$(get_consul_version)
  create_install_paths "$${DEFAULT_CONSUL_PATH}" "$${DEFAULT_CONSUL_USER}" "$${DEFAULT_CONSUL_CONFIG}" "$${DEFAULT_CONSUL_OPT}" "$${CONSUL_CLUSTER_TAG}" consul $${consul_dl_ver}
  create_service "$${DEFAULT_CONSUL_SERVICE}" consul

  log "INFO" "$${func}" "Consul install complete!"
  sudo rm -rf "$${TMP_DIR}"
}

if [ $${USE_USERDATA} -eq 1 ]; then
  main "$@"
else
  exit
fi
