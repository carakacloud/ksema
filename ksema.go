package ksema

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
)

type Ksema struct {
	serverIP string
	passKey  string
	apiKey   string
	pin      string
	client   *http.Client
	sessID   string
	userType int
}

// New return the pointer of Ksema object
//
// It automatically execute the key exchange and must be success in order to use it
func New(serverIP, passKey, apiKey, pin string) (*Ksema, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				CurvePreferences: []tls.CurveID{
					tls.X25519MLKEM768,
				},
			},
		},
	}

	k := &Ksema{
		serverIP: serverIP,
		passKey:  passKey,
		apiKey:   apiKey,
		pin:      pin,
		client:   client,
	}

	if success, err := k.keyExchange(); err != nil || !success {
		fmt.Println("Key exchange failed, please retry")
		return nil, err
	}

	return k, nil
}

// Perform key exchange with three-way encrypted handshake
func (k *Ksema) keyExchange() (bool, error) {
	var res AuthResponse

	payload := AuthRequest{
		Passkey: k.passKey,
		APIKey:  k.apiKey,
		PIN:     k.pin,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Error marshaling JSON: %v\n", err)
		return false, err
	}

	resp, err := k.client.Post(fmt.Sprintf("https://%s/api/hsm/auth", k.serverIP), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("Error making GET request: %v\n", err)
		return false, err
	}
	defer resp.Body.Close()

	// Read and print response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return false, err
	}

	err = json.Unmarshal(body, &res)
	if err != nil {
		fmt.Printf("Error unmarshaling response: %v\n", err)
		return false, err
	}

	if !res.Success {
		return false, errors.New("return auth request is false")
	}

	k.sessID = res.Data.SessionID
	k.userType = res.Data.UserType

	return true, nil
}

// Perform ping to server
// Return error if failed
func (k *Ksema) Ping() error {
	return operationPing(k.client, k.sessID, k.serverIP)
}

// Perform encrypt of a data bytes
// Return the cipher in bytes and error
//
// User object does not need to specified the key label used, except for user slot
func (k *Ksema) Encrypt(data []byte, keyLabel string) ([]byte, error) {
	if k.userType > USER_OBJECT && keyLabel == "" {
		return nil, errors.New("no key label specified")
	}
	return operationEncrypt(k.client, k.sessID, k.serverIP, data, keyLabel)
}

// Perform decrypt of a data bytes
// Return the plaintext in bytes and error
//
// User object does not need to specified the key label used, except for user slot
func (k *Ksema) Decrypt(data []byte, keyLabel string) ([]byte, error) {
	if k.userType > USER_OBJECT && keyLabel == "" {
		return nil, errors.New("no key label specified")
	}
	return operationDecrypt(k.client, k.sessID, k.serverIP, data, keyLabel)
}

// Perform signing of a data bytes
// Return the signature in bytes and error
//
// User object does not need to specified the key label used, except for user slot
func (k *Ksema) Sign(data []byte, keyLabel string) ([]byte, error) {
	if k.userType > USER_OBJECT && keyLabel == "" {
		return nil, errors.New("no key label specified")
	}
	return operationSign(k.client, k.sessID, k.serverIP, data, keyLabel)
}

// Perform verifying of a data bytes with signature
// Return error if it is invalid
//
// User object does not need to specified the key label used, except for user slot
func (k *Ksema) Verify(data, signature []byte, keyLabel string) error {
	if k.userType > USER_OBJECT && keyLabel == "" {
		return errors.New("no key label specified")
	}
	return operationVerify(k.client, k.sessID, k.serverIP, data, signature, keyLabel)
}

// Generate random data in bytes
// Return error if it is not success
//
// if the length specified is 0, it will use the default length which is 32
func (k *Ksema) Random(lenRandom uint16) ([]byte, error) {
	var lengthBytes []byte

	if lenRandom > 0 {
		lengthBytes = uint16ToBytes(lenRandom)
	} else {
		lengthBytes = nil
	}

	return operationRNG(k.client, k.sessID, k.serverIP, lengthBytes)
}

// Perform backup of a keylabel
// Return error if it is not success
//
// User object does not need to specified the key label used, except for user slot
func (k *Ksema) Backup(fileName, keyLabel string) error {
	if k.userType > USER_OBJECT && keyLabel == "" {
		return errors.New("no key label specified")
	}
	return operationBackup(k.client, k.sessID, k.serverIP, k.userType, []byte(fileName))
}

// Perform restore of a keylabel using the backed-up file
// Return error if it is not success
func (k *Ksema) Restore(fileName string) error {
	return operationRestore(k.client, k.sessID, k.serverIP, []byte(fileName))
}

// Perform deletion of a keylabel
// Return error if it is not success
func (k *Ksema) Delete(keyLabel string) error {
	if k.userType > USER_OBJECT && keyLabel == "" {
		return errors.New("no key label specified")
	}
	return operationDelete(k.client, k.sessID, k.serverIP, keyLabel)
}

// Generate key with the specified key label
// If only the first label given, it will generate symmetric key
// If both of the label is specified, it will generate asymmetric key
//
// Note that user object is not authorized to use this function
func (k *Ksema) GenKey(label1, label2 string) error {
	if label2 != "" {
		return k.genKeyAsym(label1, label2)
	}
	return k.genKeySym(label1)
}

func (k *Ksema) genKeySym(label string) error {
	return operationGenKeySym(k.client, k.sessID, k.serverIP, label)
}

func (k *Ksema) genKeyAsym(pubLabel, privLabel string) error {
	// label := fmt.Sprintf("%s;%s", pubLabel, privLabel)
	return operationGenKeyAsym(k.client, k.sessID, k.serverIP, pubLabel, privLabel)
}

// Override the default IV temporarily
// This effect will be remove if there is new session
func (k *Ksema) SetIV(iv string) error {
	if len(iv) != 16 {
		return errors.New("IV must be 16 characters")
	}
	return operationSetIV(k.client, k.sessID, k.serverIP, []byte(iv))
}

// func (k *Ksema) Close() {
// 	fmt.Println("Closing connection...")
// }
