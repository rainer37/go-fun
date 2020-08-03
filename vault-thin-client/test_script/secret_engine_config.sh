#!/usr/bin/env bash
VAULT_ADDR=http://127.0.0.1:8200
sec_path_kv=somekv
sec_path_aws=someaws
sec_path_transit=sometrainsit

vault server -dev &

sleep 2

vault secrets enable -path=$sec_path_kv kv
vault kv put $sec_path_kv/sec0 name=erlang pass=play

vault secrets enable -path=$sec_path_aws aws
vault secrets enable -path=$sec_path_transit transit