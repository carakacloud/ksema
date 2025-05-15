package ksema

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

func operationPing(client *http.Client, sessionId string, serverIP string) error {
	payload := ServiceRequest{
		SessionID: sessionId,
		Operation: "PING",
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Error marshaling JSON: %v\n", err)
		return err
	}

	resp, err := client.Post(fmt.Sprintf("https://%s/api/hsm/request", serverIP), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("Error making GET request: %v\n", err)
		return err
	}
	defer resp.Body.Close()

	// Read and print response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return err
	}

	var res ServiceResponse
	err = json.Unmarshal(body, &res)
	if err != nil {
		fmt.Printf("Error unmarshaling response: %v\n", err)
		return err
	}

	if !res.Success {
		if res.ErrorMsg != "" {
			return errors.New(res.ErrorMsg)
		}
		return errors.New("return auth request is false")
	}
	if res.Data.RetCode != SUCCESS {
		return errors.New(getReturnCodeMessage(res.Data.RetCode))
	}

	return nil
}

func operationEncrypt(client *http.Client, sessionId string, serverIP string, plainText []byte, keyLabel string) ([]byte, error) {
	var err error

	payload := ServiceRequest{
		SessionID: sessionId,
		Operation: FunctionEncrypt,
		Label:     keyLabel,
		Data:      plainText,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Error marshaling JSON: %v\n", err)
		return nil, err
	}

	resp, err := client.Post(fmt.Sprintf("https://%s/api/hsm/request", serverIP), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("Error making GET request: %v\n", err)
		return nil, err
	}
	defer resp.Body.Close()

	// Read and print response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return nil, err
	}

	var res ServiceResponse
	err = json.Unmarshal(body, &res)
	if err != nil {
		fmt.Printf("Error unmarshaling response: %v\n", err)
		return nil, err
	}

	if !res.Success {
		if res.ErrorMsg != "" {
			return nil, errors.New(res.ErrorMsg)
		}
		return nil, errors.New("return auth request is false")
	}
	if res.Data.RetCode != SUCCESS {
		return nil, errors.New(getReturnCodeMessage(res.Data.RetCode))
	}

	cipher, err := base64.StdEncoding.DecodeString(res.Data.Message)
	if err != nil {
		fmt.Printf("Error decoding return message: %v\n", err)
		return nil, err
	}

	return cipher, nil
}

func operationDecrypt(client *http.Client, sessionId string, serverIP string, cipherText []byte, keyLabel string) ([]byte, error) {
	var err error

	payload := ServiceRequest{
		SessionID: sessionId,
		Operation: FunctionDecrypt,
		Label:     keyLabel,
		Data:      cipherText,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Error marshaling JSON: %v\n", err)
		return nil, err
	}

	resp, err := client.Post(fmt.Sprintf("https://%s/api/hsm/request", serverIP), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("Error making GET request: %v\n", err)
		return nil, err
	}
	defer resp.Body.Close()

	// Read and print response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return nil, err
	}

	var res ServiceResponse
	err = json.Unmarshal(body, &res)
	if err != nil {
		fmt.Printf("Error unmarshaling response: %v\n", err)
		return nil, err
	}

	if !res.Success {
		if res.ErrorMsg != "" {
			return nil, errors.New(res.ErrorMsg)
		}
		return nil, errors.New("return auth request is false")
	}
	if res.Data.RetCode != SUCCESS {
		return nil, errors.New(getReturnCodeMessage(res.Data.RetCode))
	}

	plain, err := base64.StdEncoding.DecodeString(res.Data.Message)
	if err != nil {
		fmt.Printf("Error decoding return message: %v\n", err)
		return nil, err
	}

	return plain, nil
}

func operationSign(client *http.Client, sessionId string, serverIP string, data []byte, keyLabel string) ([]byte, error) {
	var err error

	payload := ServiceRequest{
		SessionID: sessionId,
		Operation: FunctionSign,
		Label:     keyLabel,
		Data:      data,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Error marshaling JSON: %v\n", err)
		return nil, err
	}

	resp, err := client.Post(fmt.Sprintf("https://%s/api/hsm/request", serverIP), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("Error making GET request: %v\n", err)
		return nil, err
	}
	defer resp.Body.Close()

	// Read and print response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return nil, err
	}

	var res ServiceResponse
	err = json.Unmarshal(body, &res)
	if err != nil {
		fmt.Printf("Error unmarshaling response: %v\n", err)
		return nil, err
	}

	if !res.Success {
		if res.ErrorMsg != "" {
			return nil, errors.New(res.ErrorMsg)
		}
		return nil, errors.New("return auth request is false")
	}
	if res.Data.RetCode != SUCCESS {
		return nil, errors.New(getReturnCodeMessage(res.Data.RetCode))
	}

	signature, err := base64.StdEncoding.DecodeString(res.Data.Message)
	if err != nil {
		fmt.Printf("Error decoding return message: %v\n", err)
		return nil, err
	}

	return signature, nil
}

func operationVerify(client *http.Client, sessionId string, serverIP string, data []byte, signature []byte, keyLabel string) error {
	var err error

	dataLen := len(data)
	signatureLen := len(signature)

	dataPayload := append(uint16ToBytes(uint16(dataLen)), data...)
	dataPayload = append(dataPayload, uint16ToBytes(uint16(signatureLen))...)
	dataPayload = append(dataPayload, signature...)

	payload := ServiceRequest{
		SessionID: sessionId,
		Operation: FunctionVerify,
		Label:     keyLabel,
		Data:      dataPayload,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Error marshaling JSON: %v\n", err)
		return err
	}

	resp, err := client.Post(fmt.Sprintf("https://%s/api/hsm/request", serverIP), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("Error making GET request: %v\n", err)
		return err
	}
	defer resp.Body.Close()

	// Read and print response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return err
	}

	var res ServiceResponse
	err = json.Unmarshal(body, &res)
	if err != nil {
		fmt.Printf("Error unmarshaling response: %v\n", err)
		return err
	}

	if !res.Success {
		if res.ErrorMsg != "" {
			return errors.New(res.ErrorMsg)
		}
		return errors.New("return auth request is false")
	}
	if res.Data.RetCode != SUCCESS {
		return errors.New(getReturnCodeMessage(res.Data.RetCode))
	}

	return nil
}

func operationRNG(client *http.Client, sessionId string, serverIP string, data []byte) ([]byte, error) {
	var err error

	payload := ServiceRequest{
		SessionID: sessionId,
		Operation: FunctionRNG,
		Data:      data,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Error marshaling JSON: %v\n", err)
		return nil, err
	}

	resp, err := client.Post(fmt.Sprintf("https://%s/api/hsm/request", serverIP), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("Error making GET request: %v\n", err)
		return nil, err
	}
	defer resp.Body.Close()

	// Read and print response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return nil, err
	}

	var res ServiceResponse
	err = json.Unmarshal(body, &res)
	if err != nil {
		fmt.Printf("Error unmarshaling response: %v\n", err)
		return nil, err
	}

	if !res.Success {
		if res.ErrorMsg != "" {
			return nil, errors.New(res.ErrorMsg)
		}
		return nil, errors.New("return auth request is false")
	}
	if res.Data.RetCode != SUCCESS {
		return nil, errors.New(getReturnCodeMessage(res.Data.RetCode))
	}

	random, err := base64.StdEncoding.DecodeString(res.Data.Message)
	if err != nil {
		fmt.Printf("Error decoding return message: %v\n", err)
		return nil, err
	}

	return random, nil
}

func operationBackup(client *http.Client, sessionId string, serverIP string, userType int, data []byte) error {
	var err error

	payload := ServiceRequest{
		SessionID: sessionId,
		Operation: FunctionBackup,
		Data:      data,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Error marshaling JSON: %v\n", err)
		return err
	}

	resp, err := client.Post(fmt.Sprintf("https://%s/api/hsm/request", serverIP), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("Error making GET request: %v\n", err)
		return err
	}
	defer resp.Body.Close()

	// Read and print response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return err
	}

	var res ServiceResponse
	err = json.Unmarshal(body, &res)
	if err != nil {
		fmt.Printf("Error unmarshaling response: %v\n", err)
		return err
	}

	if !res.Success {
		if res.ErrorMsg != "" {
			return errors.New(res.ErrorMsg)
		}
		return errors.New("return auth request is false")
	}
	if res.Data.RetCode != SUCCESS {
		return errors.New(getReturnCodeMessage(res.Data.RetCode))
	}

	dataBackup, err := base64.StdEncoding.DecodeString(res.Data.Message)
	if err != nil {
		fmt.Printf("Error decoding return message: %v\n", err)
		return err
	}

	headerLen := binary.BigEndian.Uint16(dataBackup[:2])
	header := dataBackup[2 : 2+headerLen]
	stringHeader := string(header)

	exportedLen := binary.BigEndian.Uint16(dataBackup[2+headerLen : 4+headerLen])
	exported := dataBackup[4+headerLen : 4+headerLen+exportedLen]
	stringExported := string(exported)

	os.WriteFile(string(data), []byte(stringHeader+"\n"+stringExported), 0644)

	if userType == USER_OBJECT {
		exportedLen2 := binary.BigEndian.Uint16(dataBackup[4+headerLen+exportedLen : 6+headerLen+exportedLen])
		exported2 := dataBackup[6+headerLen+exportedLen : 6+headerLen+exportedLen+exportedLen2]
		stringExported2 := string(exported2)
		os.WriteFile("priv"+string(data), []byte(stringHeader+"\n"+stringExported2), 0644)
	}

	return nil
}

func operationRestore(client *http.Client, sessionId string, serverIP string, data []byte) error {
	var err error

	lines, err := os.ReadFile(string(data))
	if err != nil {
		return err
	}
	content := bytes.SplitN(lines, []byte("\n"), 2)
	if len(content) < 2 {
		return errors.New("invalid backup file format")
	}
	line := content[1]

	payload := ServiceRequest{
		SessionID: sessionId,
		Operation: FunctionRestore,
		Data:      line,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Error marshaling JSON: %v\n", err)
		return err
	}

	resp, err := client.Post(fmt.Sprintf("https://%s/api/hsm/request", serverIP), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("Error making GET request: %v\n", err)
		return err
	}
	defer resp.Body.Close()

	// Read and print response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return err
	}

	var res ServiceResponse
	err = json.Unmarshal(body, &res)
	if err != nil {
		fmt.Printf("Error unmarshaling response: %v\n", err)
		return err
	}

	if !res.Success {
		if res.ErrorMsg != "" {
			return errors.New(res.ErrorMsg)
		}
		return errors.New("return auth request is false")
	}
	if res.Data.RetCode != SUCCESS {
		return errors.New(getReturnCodeMessage(res.Data.RetCode))
	}

	return nil
}

func operationDelete(client *http.Client, sessionId string, serverIP string, keyLabel string) error {
	var err error

	payload := ServiceRequest{
		SessionID: sessionId,
		Operation: FunctionDelete,
		Label:     keyLabel,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Error marshaling JSON: %v\n", err)
		return err
	}

	resp, err := client.Post(fmt.Sprintf("https://%s/api/hsm/request", serverIP), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("Error making GET request: %v\n", err)
		return err
	}
	defer resp.Body.Close()

	// Read and print response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return err
	}

	var res ServiceResponse
	err = json.Unmarshal(body, &res)
	if err != nil {
		fmt.Printf("Error unmarshaling response: %v\n", err)
		return err
	}

	if !res.Success {
		if res.ErrorMsg != "" {
			return errors.New(res.ErrorMsg)
		}
		return errors.New("return auth request is false")
	}
	if res.Data.RetCode != SUCCESS {
		return errors.New(getReturnCodeMessage(res.Data.RetCode))
	}

	return nil
}

func operationGenKeySym(client *http.Client, sessionId string, serverIP string, keyLabel string) error {
	var err error

	payload := ServiceRequest{
		SessionID: sessionId,
		Operation: FunctionGenKeySym,
		Label:     keyLabel,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Error marshaling JSON: %v\n", err)
		return err
	}

	resp, err := client.Post(fmt.Sprintf("https://%s/api/hsm/request", serverIP), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("Error making GET request: %v\n", err)
		return err
	}
	defer resp.Body.Close()

	// Read and print response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return err
	}

	var res ServiceResponse
	err = json.Unmarshal(body, &res)
	if err != nil {
		fmt.Printf("Error unmarshaling response: %v\n", err)
		return err
	}

	if !res.Success {
		if res.ErrorMsg != "" {
			return errors.New(res.ErrorMsg)
		}
		return errors.New("return auth request is false")
	}
	if res.Data.RetCode != SUCCESS {
		return errors.New(getReturnCodeMessage(res.Data.RetCode))
	}

	return nil
}

func operationGenKeyAsym(client *http.Client, sessionId string, serverIP string, pubLabel, privLabel string) error {
	var err error

	payload := ServiceRequest{
		SessionID: sessionId,
		Operation: FunctionGenKeyAsym,
		Label:     fmt.Sprintf("%s;%s", pubLabel, privLabel),
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Error marshaling JSON: %v\n", err)
		return err
	}

	resp, err := client.Post(fmt.Sprintf("https://%s/api/hsm/request", serverIP), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("Error making GET request: %v\n", err)
		return err
	}
	defer resp.Body.Close()

	// Read and print response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return err
	}

	var res ServiceResponse
	err = json.Unmarshal(body, &res)
	if err != nil {
		fmt.Printf("Error unmarshaling response: %v\n", err)
		return err
	}

	if !res.Success {
		if res.ErrorMsg != "" {
			return errors.New(res.ErrorMsg)
		}
		return errors.New("return auth request is false")
	}
	if res.Data.RetCode != SUCCESS {
		return errors.New(getReturnCodeMessage(res.Data.RetCode))
	}

	return nil
}

func operationSetIV(client *http.Client, sessionId string, serverIP string, data []byte) error {
	var err error

	payload := ServiceRequest{
		SessionID: sessionId,
		Operation: FunctionSetIV,
		Data:      data,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("Error marshaling JSON: %v\n", err)
		return err
	}

	resp, err := client.Post(fmt.Sprintf("https://%s/api/hsm/request", serverIP), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Printf("Error making GET request: %v\n", err)
		return err
	}
	defer resp.Body.Close()

	// Read and print response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return err
	}

	var res ServiceResponse
	err = json.Unmarshal(body, &res)
	if err != nil {
		fmt.Printf("Error unmarshaling response: %v\n", err)
		return err
	}

	if !res.Success {
		if res.ErrorMsg != "" {
			return errors.New(res.ErrorMsg)
		}
		return errors.New("return auth request is false")
	}
	if res.Data.RetCode != SUCCESS {
		return errors.New(getReturnCodeMessage(res.Data.RetCode))
	}

	return nil
}

func getReturnCodeMessage(code int) string {
	if msg, exists := mapRetCodeToString[code]; exists {
		return msg
	}
	return "Unknown return"
}

func uint16ToBytes(num uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, num)
	return b
}

func uint32ToBytes(num uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, num)
	return b
}
