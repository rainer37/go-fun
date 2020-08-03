#!/usr/bin/env bash
VAULT_ADDR=http://127.0.0.1:8200
auth_path=upass
auth_path_approle=arole

vault server -dev-listen-address=VAULT_ADDR &

sleep 2

vault auth enable -path=$auth_path userpass
vault write auth/$auth_path/users/adam password=foo policies=default
vault write auth/$auth_path/users/perl password=passw0rd policies=default
vault write auth/$auth_path/users/java password=beans policies=default

vault auth enable -path=$auth_path_approle approle
vault write auth/arole/role/my-role secret_id_ttl=10m token_num_uses=10 token_ttl=20m token_max_ttl=30m secret_id_num_uses=40
