terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aci = {
      source  = "CiscoDevNet/aci"
      version = ">2.20.0"
    }
  }

   backend "pg" {
    # conn_str and schema_name supplied via -backend-config at init
  }
}


provider "aci" {
  # Credentials supplied via ACI_URL / ACI_USERNAME / ACI_PASSWORD
  insecure = true
  retries  = 5
}

module "aci" {
  # source = "github.com/netascode/terraform-aci-nac-aci?ref=main"
  source  = "netascode/nac-aci/aci"
  version = "~> 2.0"

  yaml_directories = ["data"]

  manage_access_policies    = false
  manage_fabric_policies    = false
  manage_pod_policies       = false
  manage_node_policies      = false
  manage_interface_policies = false
  manage_tenants            = true
}