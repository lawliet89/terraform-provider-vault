---
layout: "vault"
page_title: "Vault: vault_database_secret_backend_connection resource"
sidebar_current: "docs-vault-resource-database-secret-backend-connection"
description: |-
  Configures a database secret backend connection for Vault.
---

# vault\_database\_secret\_backend\_connection

Creates a Database Secret Backend connection in Vault. Database secret backend
connections can be used to generate dynamic credentials for the database.

~> **Important** All data provided in the resource configuration will be
written in cleartext to state and plan files generated by Terraform, and
will appear in the console output when Terraform runs. Protect these
artifacts accordingly. See
[the main provider documentation](../index.html)
for more details.

## Example Usage

```hcl
resource "vault_mount" "db" {
  path = "postgres"
  type = "database"
}

resource "vault_database_secret_backend" "postgres" {
  backend       = "${vault_mount.db.path}"
  name          = "postgres"
  allowed_roles = ["dev", "prod"]

  postgresql {
    connection_url = "postgres://username:password@host:port/database"
  }
}
```

## Argument Reference

The following arguments are supported:

* `name` - (Required) A unique name to give the database connection.

* `backend` - (Required) The unique name of the Vault mount to configure.

* `verify_connection` - (Optional) Whether the connection should be verified on
  initial configuration or not.

* `allowed_roles` - (Optional) A list of roles that are allowed to use this
  connection.

* `cassandra` - (Optional) Configuration options for Cassandra connections.

* `mongodb` - (Optional) Configuration options for MongoDB connections.

* `hana` - (Optional) Configuration options for SAP HanaDB connections.

* `mssql` - (Optional) Configuration options for MSSQL connections.

* `mysql` - (Optional) Configuration options for MySQL connections.

* `postgresql` - (Optional) Configuration options for PostgreSQL connections.

* `oracle` - (Optional) Configuration options for Oracle connections.

### Cassandra Configuration Options

* `hosts` - (Required) The hosts to connect to.

* `username` - (Required) The username to authenticate with.

* `password` - (Required) The password to authenticate with.

* `port` - (Optional) The default port to connect to if no port is specified as
  part of the host.

* `tls` - (Optional) Whether to use TLS when connecting to Cassandra.

* `insecure_tls` - (Optional) Whether to skip verification of the server
  certificate when using TLS.

* `pem_bundle` - (Optional) Concatenated PEM blocks configuring the certificate
  chain.

* `pem_json` - (Optional) A JSON structure configuring the certificate chain.

* `protocol_version` - (Optional) The CQL protocol version to use.

* `connect_timeout` - (Optional) The number of seconds to use as a connection
  timeout.

### MongoDB Configuration Options

* `connection_url` - (Required) A URL containing connection information. See
  the [Vault
  docs](https://www.vaultproject.io/api/secret/databases/mongodb.html#sample-payload)
  for an example.

### SAP HanaDB Configuration Options

* `connection_url` - (Required) A URL containing connection information. See
  the [Vault
  docs](https://www.vaultproject.io/api/secret/databases/hanadb.html#sample-payload)
  for an example.

* `max_open_connections` - (Optional) The maximum number of open connections to
  use.

* `max_idle_connections` - (Optional) The maximum number of idle connections to
  maintain.

* `max_connection_lifetime` - (Optional) The maximum number of seconds to keep
  a connection alive for.

### MSSQL Configuration Options

* `connection_url` - (Required) A URL containing connection information. See
  the [Vault
  docs](https://www.vaultproject.io/api/secret/databases/mssql.html#sample-payload)
  for an example.

* `max_open_connections` - (Optional) The maximum number of open connections to
  use.

* `max_idle_connections` - (Optional) The maximum number of idle connections to
  maintain.

* `max_connection_lifetime` - (Optional) The maximum number of seconds to keep
  a connection alive for.

### MySQL Configuration Options

* `connection_url` - (Required) A URL containing connection information. See
  the [Vault
  docs](https://www.vaultproject.io/api/secret/databases/mysql.html#sample-payload)
  for an example.

* `max_open_connections` - (Optional) The maximum number of open connections to
  use.

* `max_idle_connections` - (Optional) The maximum number of idle connections to
  maintain.

* `max_connection_lifetime` - (Optional) The maximum number of seconds to keep
  a connection alive for.

### PostgreSQL Configuration Options

* `connection_url` - (Required) A URL containing connection information. See
  the [Vault
  docs](https://www.vaultproject.io/api/secret/databases/postgresql.html#sample-payload)
  for an example.

* `max_open_connections` - (Optional) The maximum number of open connections to
  use.

* `max_idle_connections` - (Optional) The maximum number of idle connections to
  maintain.

* `max_connection_lifetime` - (Optional) The maximum number of seconds to keep
  a connection alive for.

### Oracle Configuration Options

* `connection_url` - (Required) A URL containing connection information. See
  the [Vault
  docs](https://www.vaultproject.io/api/secret/databases/oracle.html#sample-payload)
  for an example.

* `max_open_connections` - (Optional) The maximum number of open connections to
  use.

* `max_idle_connections` - (Optional) The maximum number of idle connections to
  maintain.

* `max_connection_lifetime` - (Optional) The maximum number of seconds to keep
  a connection alive for.

## Attributes Reference

No additional attributes are exported by this resource.