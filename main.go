package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

func main() {
	var (
		vaultURL = flag.String("vault-url", "", "Azure Key Vault URL (e.g., https://myvault.vault.azure.net/)")
		keyName  = flag.String("key-name", "", "Name of the key to test")
	)
	flag.Parse()

	if *vaultURL == "" || *keyName == "" {
		flag.Usage()
		os.Exit(1)
	}

	ctx := context.Background()

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("Failed to obtain credentials: %v", err)
	}

	client, err := azkeys.NewClient(*vaultURL, cred, nil)
	if err != nil {
		log.Fatalf("Failed to create Key Vault client: %v", err)
	}

	fmt.Printf("Testing Azure Key Vault permissions for key: %s\n", *keyName)
	fmt.Printf("Vault URL: %s\n\n", *vaultURL)

	testData := []byte("Test message for Azure Key Vault signing and verification")
	hash := sha256.Sum256(testData)

	fmt.Println("1. Testing SIGN permission...")
	signature, err := testSign(ctx, client, *keyName, hash[:])
	if err != nil {
		fmt.Printf("   ❌ SIGN failed: %v\n", err)
	} else {
		fmt.Printf("   ✅ SIGN successful\n")
		fmt.Printf("   Signature: %s\n", base64.StdEncoding.EncodeToString(signature))
	}

	fmt.Println("\n2. Testing VERIFY permission...")
	if signature != nil {
		err = testVerify(ctx, client, *keyName, hash[:], signature)
		if err != nil {
			fmt.Printf("   ❌ VERIFY failed: %v\n", err)
		} else {
			fmt.Printf("   ✅ VERIFY successful\n")
		}
	} else {
		fmt.Println("   ⚠️  Skipping VERIFY test (no signature available)")
	}

	fmt.Println("\n3. Testing GET permission (key info retrieval)...")
	err = testGetKey(ctx, client, *keyName)
	if err != nil {
		fmt.Printf("   ❌ GET failed: %v\n", err)
	} else {
		fmt.Printf("   ✅ GET successful\n")
	}

	fmt.Println("\nPermission test completed.")
}

func testSign(ctx context.Context, client *azkeys.Client, keyName string, digest []byte) ([]byte, error) {
	signParams := azkeys.SignParameters{
		Algorithm: to.Ptr(azkeys.SignatureAlgorithmRS256),
		Value:     digest,
	}

	resp, err := client.Sign(ctx, keyName, "", signParams, nil)
	if err != nil {
		return nil, fmt.Errorf("sign operation failed: %w", err)
	}

	return resp.Result, nil
}

func testVerify(ctx context.Context, client *azkeys.Client, keyName string, digest []byte, signature []byte) error {
	verifyParams := azkeys.VerifyParameters{
		Algorithm: to.Ptr(azkeys.SignatureAlgorithmRS256),
		Digest:    digest,
		Signature: signature,
	}

	resp, err := client.Verify(ctx, keyName, "", verifyParams, nil)
	if err != nil {
		return fmt.Errorf("verify operation failed: %w", err)
	}

	if resp.Value != nil && *resp.Value {
		return nil
	}

	return fmt.Errorf("signature verification failed")
}

func testGetKey(ctx context.Context, client *azkeys.Client, keyName string) error {
	resp, err := client.GetKey(ctx, keyName, "", nil)
	if err != nil {
		return fmt.Errorf("get key operation failed: %w", err)
	}

	if resp.Key.KID != nil {
		fmt.Printf("   Key ID: %s\n", *resp.Key.KID)
	}
	if resp.Key.Kty != nil {
		fmt.Printf("   Key Type: %s\n", *resp.Key.Kty)
	}

	return nil
}

func to[T any](v T) *T {
	return &v
}