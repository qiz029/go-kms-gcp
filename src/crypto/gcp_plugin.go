package crypto

import (
	"encoding/base64"
	"fmt"
	"log"

	"golang.org/x/net/context"
	"golang.org/x/oauth2/google"

	cloudkms "google.golang.org/api/cloudkms/v1"
)

func Init() {
	_ = context.Background
	_ = google.DefaultClient
}

func CreateKeyring(project, location, name string) error {
	ctx := context.Background()
	authedClient, err := google.DefaultClient(ctx, cloudkms.CloudPlatformScope)
	if err != nil {
		return err
	}
	client, err := cloudkms.New(authedClient)
	if err != nil {
		return err
	}
	parent := fmt.Sprintf("projects/%s/locations/%s", project, location)

	_, err = client.Projects.Locations.KeyRings.Create(
		parent, &cloudkms.KeyRing{}).KeyRingId(name).Do()
	if err != nil {
		return err
	}
	log.Print("Created key ring.")

	return nil
}

func CreateCryptoKey(project, keyRing, location, key string) error {
	ctx := context.Background()
	authedClient, err := google.DefaultClient(ctx, cloudkms.CloudPlatformScope)
	if err != nil {
		return err
	}
	client, err := cloudkms.New(authedClient)
	if err != nil {
		return err
	}
	parent := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s", project, location, keyRing)
	purpose := "ENCRYPT_DECRYPT"

	_, err = client.Projects.Locations.KeyRings.CryptoKeys.Create(
		parent, &cloudkms.CryptoKey{
			Purpose: purpose,
		}).CryptoKeyId(key).Do()
	if err != nil {
		return err
	}
	log.Print("Created crypto key.")

	return nil
}

func Encrypt(projectID, locationID, keyRingID, cryptoKeyID string, plaintext []byte) ([]byte, error) {
	ctx := context.Background()
	client, err := google.DefaultClient(ctx, cloudkms.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	cloudkmsService, err := cloudkms.New(client)
	if err != nil {
		return nil, err
	}

	parentName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
		projectID, locationID, keyRingID, cryptoKeyID)

	req := &cloudkms.EncryptRequest{
		Plaintext: base64.StdEncoding.EncodeToString(plaintext),
	}
	resp, err := cloudkmsService.Projects.Locations.KeyRings.CryptoKeys.Encrypt(parentName, req).Do()
	if err != nil {
		return nil, err
	}

	return base64.StdEncoding.DecodeString(resp.Ciphertext)
}

func Decrypt(projectID, locationID, keyRingID, cryptoKeyID string, ciphertext []byte) ([]byte, error) {
	ctx := context.Background()
	client, err := google.DefaultClient(ctx, cloudkms.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	cloudkmsService, err := cloudkms.New(client)
	if err != nil {
		return nil, err
	}

	parentName := fmt.Sprintf("projects/%s/locations/%s/keyRings/%s/cryptoKeys/%s",
		projectID, locationID, keyRingID, cryptoKeyID)

	req := &cloudkms.DecryptRequest{
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	resp, err := cloudkmsService.Projects.Locations.KeyRings.CryptoKeys.Decrypt(parentName, req).Do()
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(resp.Plaintext)
}
