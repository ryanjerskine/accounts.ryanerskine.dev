provider "azurerm" {
  subscription_id = ""
  client_id       = ""
  client_secret   = ""
  tenant_id       = ""
}
locals {
  tags = {
    "environment" = "development"
  }
}
resource "azurerm_resource_group" "dev" {
  name     = "rje-resource-group"
  location = "Central US"
  tags     = "${local.tags}"
}
resource "azurerm_key_vault" "dev" {
  name                        = "rje-keyvault"
  location                    = "${azurerm_resource_group.dev.location}",
  resource_group_name         = "${azurerm_resource_group.dev.name}"
  tenant_id                   = ""
  tags                        = "${local.tags}"
}
resource "azurerm_key_vault_certificate" "dev" {
  name               = "rje-identityserver"
  key_vault_id       = "${azurerm_key_vault.dev.id}"
  certificate_policy {
    issuer_parameters {
      name = "Self"
    }
    key_properties {
      exportable = true
      key_size   = 4096
      key_type   = "RSA"
      reuse_key  = true
    }
    lifetime_action {
      action {
        action_type = "AutoRenew"
      }
      trigger {
        lifetime_percentage = 80
      }
    }
    secret_properties {
      content_type = "application/x-pkcs12"
    }
    x509_certificate_properties {
      key_usage = [
        "cRLSign",
        "dataEncipherment",
        "digitalSignature",
        "keyAgreement",
        "keyCertSign",
        "keyEncipherment",
      ]
      subject            = "CN=accounts.ryanerskine.dev"
      validity_in_months = 3
    }
  }
  tags = "${local.tags}"
}
resource "azurerm_container_registry" "dev" {
  name                = "rjeContainerRegistry"
  resource_group_name = "${azurerm_resource_group.dev.name}"
  location            = "${azurerm_resource_group.dev.location}"
  sku                 = "Basic"
  tags                = "${local.tags}"
}
resource "azurerm_sql_server" "dev" {
  name                         = "rje-database-server"
  resource_group_name          = "${azurerm_resource_group.dev.name}"
  location                     = "Central US"
  version                      = "12.0"
  administrator_login          = "mradmin"
  administrator_login_password = "mrAdminsP@ssword"
  tags                         = "${local.tags}"
}
resource "azurerm_sql_firewall_rule" "dev" {
  name                = "AllowAzureServices"
  resource_group_name = "${azurerm_resource_group.dev.name}"
  server_name         = "${azurerm_sql_server.dev.name}"
  start_ip_address    = "0.0.0.0"
  end_ip_address      = "0.0.0.0"
}
resource "azurerm_sql_database" "dev" {
  name                = "rje-website-database"
  resource_group_name = "${azurerm_resource_group.dev.name}"
  location            = "Central US"
  server_name         = "${azurerm_sql_server.dev.name}"
  tags                = "${local.tags}"
}
