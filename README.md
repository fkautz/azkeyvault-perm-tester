# Azure Key Vault Permissions Tester

This Go program tests whether you have appropriate permissions to sign and verify using Azure Key Vault.

## Usage

```bash
go run main.go -vault-url https://yourvault.vault.azure.net/ -key-name your-key-name
```

## Prerequisites

- Azure CLI installed and authenticated (`az login`)
- A Key Vault with a key created
- Appropriate permissions assigned to your identity

## Permissions Tested

1. **SIGN** - Ability to sign data with the key
2. **VERIFY** - Ability to verify signatures
3. **GET** - Ability to retrieve key information

## Building

```bash
go build -o azkeyvault-perm-tester
./azkeyvault-perm-tester -vault-url https://yourvault.vault.azure.net/ -key-name your-key-name
```