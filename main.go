package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

func main() {
	var (
		vaultURL   = flag.String("vault-url", "", "Azure Key Vault URL (e.g., https://myvault.vault.azure.net/)")
		keyName    = flag.String("key-name", "", "Name of the key to test")
		testSign   = flag.Bool("test-sign", true, "Test signing permission")
		testVerify = flag.Bool("test-verify", true, "Test verification permission")
		testGet    = flag.Bool("test-get", true, "Test get key permission")
		skipAll    = flag.Bool("skip-all", false, "Skip all tests by default (use with specific test flags)")
		algorithm  = flag.String("algorithm", "RS256", "Signature algorithm to use (RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES256K, ES384, ES512)")
	)
	flag.Parse()

	if *vaultURL == "" || *keyName == "" {
		flag.Usage()
		os.Exit(1)
	}

	if *skipAll {
		*testSign = false
		*testVerify = false
		*testGet = false
		
		// Re-parse to honor any explicitly set test flags
		flag.Visit(func(f *flag.Flag) {
			switch f.Name {
			case "test-sign":
				*testSign = true
			case "test-verify":
				*testVerify = true
			case "test-get":
				*testGet = true
			}
		})
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

	// Use the specified signature algorithm
	sigAlgorithm := azkeys.SignatureAlgorithm(*algorithm)

	fmt.Printf("Testing Azure Key Vault permissions for key: %s\n", *keyName)
	fmt.Printf("Vault URL: %s\n", *vaultURL)
	fmt.Printf("Algorithm: %s\n", sigAlgorithm)
	fmt.Println("Note: HSM vs Software keys are determined by the key's protection level, not the algorithm\n")

	testData := []byte("Test message for Azure Key Vault signing and verification")
	hash := sha256.Sum256(testData)
	
	var signature []byte
	testNum := 1

	if *testSign {
		fmt.Printf("%d. Testing SIGN permission...\n", testNum)
		testNum++
		var err error
		signature, err = doTestSign(ctx, client, *keyName, hash[:], sigAlgorithm)
		if err != nil {
			fmt.Printf("   ❌ SIGN failed: %v\n", err)
		} else {
			fmt.Printf("   ✅ SIGN successful\n")
			fmt.Printf("   Signature: %s\n", base64.StdEncoding.EncodeToString(signature))
		}
		fmt.Println()
	}

	if *testVerify {
		fmt.Printf("%d. Testing VERIFY permission...\n", testNum)
		testNum++
		
		// For standalone verify test, create a dummy signature if we don't have one
		if signature == nil && !*testSign {
			fmt.Println("   ℹ️  No signature available from sign test, using dummy signature for verify test")
			signature = make([]byte, 256) // RSA-2048 signature size
		}
		
		if signature != nil {
			err := doTestVerify(ctx, client, *keyName, hash[:], signature, sigAlgorithm)
			if err != nil {
				fmt.Printf("   ❌ VERIFY failed: %v\n", err)
			} else {
				fmt.Printf("   ✅ VERIFY successful\n")
			}
		}
		fmt.Println()
	}

	if *testGet {
		fmt.Printf("%d. Testing GET permission (key info retrieval)...\n", testNum)
		keyInfo, err := doTestGetKey(ctx, client, *keyName)
		if err != nil {
			fmt.Printf("   ❌ GET failed: %v\n", err)
		} else {
			fmt.Printf("   ✅ GET successful\n")
			if keyInfo != nil {
				fmt.Printf("   Key Type: %s\n", keyInfo.keyType)
				fmt.Printf("   HSM Protected: %v\n", keyInfo.hsmProtected)
			}
		}
		fmt.Println()
	}

	if !*testSign && !*testVerify && !*testGet {
		fmt.Println("No tests selected. Use -test-sign, -test-verify, or -test-get flags.")
	}

	fmt.Println("Permission test completed.")
}

func doTestSign(ctx context.Context, client *azkeys.Client, keyName string, digest []byte, algorithm azkeys.SignatureAlgorithm) ([]byte, error) {
	signParams := azkeys.SignParameters{
		Algorithm: &algorithm,
		Value:     digest,
	}

	resp, err := client.Sign(ctx, keyName, "", signParams, nil)
	if err != nil {
		return nil, fmt.Errorf("sign operation failed: %w", err)
	}

	return resp.Result, nil
}

func doTestVerify(ctx context.Context, client *azkeys.Client, keyName string, digest []byte, signature []byte, algorithm azkeys.SignatureAlgorithm) error {
	verifyParams := azkeys.VerifyParameters{
		Algorithm: &algorithm,
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

type keyInfo struct {
	keyType      string
	hsmProtected bool
}

func doTestGetKey(ctx context.Context, client *azkeys.Client, keyName string) (*keyInfo, error) {
	resp, err := client.GetKey(ctx, keyName, "", nil)
	if err != nil {
		return nil, fmt.Errorf("get key operation failed: %w", err)
	}

	info := &keyInfo{}
	
	if resp.Key.KID != nil {
		fmt.Printf("   Key ID: %s\n", *resp.Key.KID)
	}
	if resp.Key.Kty != nil {
		info.keyType = string(*resp.Key.Kty)
		
		// Check if it's an HSM key by looking at the key type suffix
		if string(*resp.Key.Kty) == "RSA-HSM" || string(*resp.Key.Kty) == "EC-HSM" {
			info.hsmProtected = true
		}
	}

	return info, nil
}