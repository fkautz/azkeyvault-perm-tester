# Azure Key Vault Permissions Tester

This Go program tests whether you have appropriate permissions to sign and verify using Azure Key Vault.

## Usage

```bash
# Test all permissions (default)
go run main.go -vault-url https://yourvault.vault.azure.net/ -key-name your-key-name

# Test only signing
go run main.go -vault-url https://yourvault.vault.azure.net/ -key-name your-key-name -skip-all -test-sign

# Test only verification
go run main.go -vault-url https://yourvault.vault.azure.net/ -key-name your-key-name -skip-all -test-verify

# Test only get key info
go run main.go -vault-url https://yourvault.vault.azure.net/ -key-name your-key-name -skip-all -test-get

# Test specific permissions
go run main.go -vault-url https://yourvault.vault.azure.net/ -key-name your-key-name -test-sign=false -test-verify=true -test-get=false

# Test with different algorithms
go run main.go -vault-url https://yourvault.vault.azure.net/ -key-name your-key-name -algorithm RS384
go run main.go -vault-url https://yourvault.vault.azure.net/ -key-name your-key-name -algorithm PS256

# Test HSM key signing (HSM keys are automatically detected)
go run main.go -vault-url https://yourvault.vault.azure.net/ -key-name your-hsm-key -skip-all -test-sign

# Test EC key with ES256 algorithm
go run main.go -vault-url https://yourvault.vault.azure.net/ -key-name your-ec-key -algorithm ES256
```

## Prerequisites

- Azure CLI installed and authenticated (`az login`)
- A Key Vault with a key created
- Appropriate permissions assigned to your identity

## Permissions Tested

1. **SIGN** - Ability to sign data with the key
2. **VERIFY** - Ability to verify signatures
3. **GET** - Ability to retrieve key information

## Command Line Flags

- `-vault-url` - Azure Key Vault URL (required)
- `-key-name` - Name of the key to test (required)
- `-test-sign` - Test signing permission (default: true)
- `-test-verify` - Test verification permission (default: true)
- `-test-get` - Test get key permission (default: true)
- `-skip-all` - Skip all tests by default, use with specific test flags
- `-algorithm` - Signature algorithm to use (default: RS256)
  - RSA: RS256, RS384, RS512, PS256, PS384, PS512
  - EC: ES256, ES256K, ES384, ES512

## HSM Key Support

The program automatically detects whether a key is HSM-protected by checking the key type (RSA-HSM or EC-HSM). Use the same algorithms for both software and HSM keys.

## Building

```bash
go build -o azkeyvault-perm-tester

# Run with default settings
./azkeyvault-perm-tester -vault-url https://yourvault.vault.azure.net/ -key-name your-key-name

# Test HSM key with PS256 algorithm
./azkeyvault-perm-tester -vault-url https://yourvault.vault.azure.net/ -key-name your-hsm-key -algorithm PS256
```

## Authentication

The program uses Azure DefaultAzureCredential, which tries the following authentication methods in order:

1. Environment variables (`AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`)
2. Managed Identity (when running in Azure)
3. Azure CLI (`az login`)
4. Azure PowerShell
5. Interactive browser authentication

For local development, the easiest method is to use Azure CLI:
```bash
az login
az account set --subscription <your-subscription-id>
```

## Example Output

```
Testing Azure Key Vault permissions for key: mykey
Vault URL: https://myvault.vault.azure.net/
Algorithm: RS256
Note: HSM vs Software keys are determined by the key's protection level, not the algorithm

1. Testing SIGN permission...
   ✅ SIGN successful
   Signature: MEQCIHx5K9...

2. Testing VERIFY permission...
   ✅ VERIFY successful

3. Testing GET permission (key info retrieval)...
   ✅ GET successful
   Key ID: https://myvault.vault.azure.net/keys/mykey/abc123
   Key Type: RSA-HSM
   HSM Protected: true

Permission test completed.
```

## Troubleshooting

### Common Issues

1. **Authentication Failed**
   - Ensure you're logged in: `az login`
   - Check your subscription: `az account show`
   - Verify your identity has access to the Key Vault

2. **Key Not Found**
   - Verify the key name is correct
   - Ensure the key exists: `az keyvault key list --vault-name <vault-name>`

3. **Permission Denied**
   - Check Key Vault access policies
   - Required permissions: `key/get`, `key/sign`, `key/verify`
   - Add permissions: `az keyvault set-policy --name <vault-name> --upn <your-email> --key-permissions get sign verify`

4. **Algorithm Mismatch**
   - RSA keys support: RS256, RS384, RS512, PS256, PS384, PS512
   - EC keys support: ES256, ES256K, ES384, ES512
   - Match algorithm to your key type