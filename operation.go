package ksema

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
		return err
	}

	resp, err := client.Post(fmt.Sprintf("https://%s/api/hsm/request", serverIP), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	var res ServiceResponse
	err = json.Unmarshal(body, &res)
	if err != nil {
		return err
	}

	if !res.Success {
		if res.ErrorMsg != "" {
			return errors.New(res.ErrorMsg)
		}
		return errors.New("return ping request is false")
	}
	if res.Data.RetCode != success {
		return errors.New(getReturnCodeMessage(res.Data.RetCode))
	}

	return nil
}

func operationEncrypt(client *http.Client, sessionId string, serverIP string, plainText []byte, keyLabel string) ([]byte, error) {
	var err error

	payload := ServiceRequest{
		SessionID: sessionId,
		Operation: functionEncrypt,
		Label:     keyLabel,
		Data:      plainText,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	resp, err := client.Post(fmt.Sprintf("https://%s/api/hsm/request", serverIP), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	var res ServiceResponse
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, err
	}

	if !res.Success {
		if res.ErrorMsg != "" {
			return nil, errors.New(res.ErrorMsg)
		}
		return nil, errors.New("return encrypt request is false")
	}
	if res.Data.RetCode != success {
		return nil, errors.New(getReturnCodeMessage(res.Data.RetCode))
	}

	cipher, err := base64.StdEncoding.DecodeString(res.Data.Message)
	if err != nil {
		return nil, err
	}

	return cipher, nil
}

func operationDecrypt(client *http.Client, sessionId string, serverIP string, cipherText []byte, keyLabel string) ([]byte, error) {
	var err error

	payload := ServiceRequest{
		SessionID: sessionId,
		Operation: functionDecrypt,
		Label:     keyLabel,
		Data:      cipherText,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	resp, err := client.Post(fmt.Sprintf("https://%s/api/hsm/request", serverIP), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	var res ServiceResponse
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, err
	}

	if !res.Success {
		if res.ErrorMsg != "" {
			return nil, errors.New(res.ErrorMsg)
		}
		return nil, errors.New("return decrypt request is false")
	}
	if res.Data.RetCode != success {
		return nil, errors.New(getReturnCodeMessage(res.Data.RetCode))
	}

	plain, err := base64.StdEncoding.DecodeString(res.Data.Message)
	if err != nil {
		return nil, err
	}

	return plain, nil
}

func operationSign(client *http.Client, sessionId string, serverIP string, operation string, data []byte, keyLabel string) ([]byte, error) {
	var err error

	payload := ServiceRequest{
		SessionID: sessionId,
		Operation: operation,
		Label:     keyLabel,
		Data:      data,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	resp, err := client.Post(fmt.Sprintf("https://%s/api/hsm/request", serverIP), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	var res ServiceResponse
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, err
	}

	if !res.Success {
		if res.ErrorMsg != "" {
			return nil, errors.New(res.ErrorMsg)
		}
		return nil, errors.New("return sign request is false")
	}
	if res.Data.RetCode != success {
		return nil, errors.New(getReturnCodeMessage(res.Data.RetCode))
	}

	signature, err := base64.StdEncoding.DecodeString(res.Data.Message)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func operationVerify(client *http.Client, sessionId string, serverIP string, operation string, data []byte, signature []byte, keyLabel string) error {
	var err error

	dataLen := len(data)
	signatureLen := len(signature)

	dataPayload := append(uint16ToBytes(uint16(dataLen)), data...)
	dataPayload = append(dataPayload, uint16ToBytes(uint16(signatureLen))...)
	dataPayload = append(dataPayload, signature...)

	payload := ServiceRequest{
		SessionID: sessionId,
		Operation: operation,
		Label:     keyLabel,
		Data:      dataPayload,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := client.Post(fmt.Sprintf("https://%s/api/hsm/request", serverIP), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	var res ServiceResponse
	err = json.Unmarshal(body, &res)
	if err != nil {
		return err
	}

	if !res.Success {
		if res.ErrorMsg != "" {
			return errors.New(res.ErrorMsg)
		}
		return errors.New("return verify request is false")
	}
	if res.Data.RetCode != success {
		return errors.New(getReturnCodeMessage(res.Data.RetCode))
	}

	return nil
}

func operationRNG(client *http.Client, sessionId string, serverIP string, data []byte) ([]byte, error) {
	var err error

	payload := ServiceRequest{
		SessionID: sessionId,
		Operation: functionRNG,
		Data:      data,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	resp, err := client.Post(fmt.Sprintf("https://%s/api/hsm/request", serverIP), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	var res ServiceResponse
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, err
	}

	if !res.Success {
		if res.ErrorMsg != "" {
			return nil, errors.New(res.ErrorMsg)
		}
		return nil, errors.New("return random request is false")
	}
	if res.Data.RetCode != success {
		return nil, errors.New(getReturnCodeMessage(res.Data.RetCode))
	}

	random, err := base64.StdEncoding.DecodeString(res.Data.Message)
	if err != nil {
		return nil, err
	}

	return random, nil
}

func operationBackup(client *http.Client, sessionId string, serverIP string, userType int, data []byte, keyLabel string) error {
	var err error

	payload := ServiceRequest{
		SessionID: sessionId,
		Operation: functionBackup,
		Data:      data,
		Label:     keyLabel,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := client.Post(fmt.Sprintf("https://%s/api/hsm/request", serverIP), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	var res ServiceResponse
	err = json.Unmarshal(body, &res)
	if err != nil {
		return err
	}

	if !res.Success {
		if res.ErrorMsg != "" {
			return errors.New(res.ErrorMsg)
		}
		return errors.New("return backup request is false")
	}
	if res.Data.RetCode != success {
		return errors.New(getReturnCodeMessage(res.Data.RetCode))
	}

	dataBackup, err := base64.StdEncoding.DecodeString(res.Data.Message)
	if err != nil {
		return err
	}

	headerLen := binary.BigEndian.Uint16(dataBackup[:2])
	header := dataBackup[2 : 2+headerLen]
	stringHeader := string(header)

	exportedLen := binary.BigEndian.Uint16(dataBackup[2+headerLen : 4+headerLen])
	exported := dataBackup[4+headerLen : 4+headerLen+exportedLen]
	stringExported := string(exported)

	os.WriteFile(string(data), []byte(stringHeader+"\n"+stringExported), 0644)

	if userType == userObject {
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
		Operation: functionRestore,
		Data:      line,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := client.Post(fmt.Sprintf("https://%s/api/hsm/request", serverIP), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	var res ServiceResponse
	err = json.Unmarshal(body, &res)
	if err != nil {
		return err
	}

	if !res.Success {
		if res.ErrorMsg != "" {
			return errors.New(res.ErrorMsg)
		}
		return errors.New("return restore request is false")
	}
	if res.Data.RetCode != success {
		return errors.New(getReturnCodeMessage(res.Data.RetCode))
	}

	return nil
}

func operationDelete(client *http.Client, sessionId string, serverIP string, keyLabel string) error {
	var err error

	payload := ServiceRequest{
		SessionID: sessionId,
		Operation: functionDelete,
		Label:     keyLabel,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := client.Post(fmt.Sprintf("https://%s/api/hsm/request", serverIP), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	var res ServiceResponse
	err = json.Unmarshal(body, &res)
	if err != nil {
		return err
	}

	if !res.Success {
		if res.ErrorMsg != "" {
			return errors.New(res.ErrorMsg)
		}
		return errors.New("return delete request is false")
	}
	if res.Data.RetCode != success {
		return errors.New(getReturnCodeMessage(res.Data.RetCode))
	}

	return nil
}

func operationGenKeySym(client *http.Client, sessionId string, serverIP string, keyLabel string) error {
	var err error

	payload := ServiceRequest{
		SessionID: sessionId,
		Operation: functionGenKeySym,
		Label:     keyLabel,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := client.Post(fmt.Sprintf("https://%s/api/hsm/request", serverIP), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	var res ServiceResponse
	err = json.Unmarshal(body, &res)
	if err != nil {
		return err
	}

	if !res.Success {
		if res.ErrorMsg != "" {
			return errors.New(res.ErrorMsg)
		}
		return errors.New("return genkey request is false")
	}
	if res.Data.RetCode != success {
		return errors.New(getReturnCodeMessage(res.Data.RetCode))
	}

	return nil
}

func operationGenKeyAsym(client *http.Client, sessionId string, serverIP string, pubLabel, privLabel string) error {
	var err error

	payload := ServiceRequest{
		SessionID: sessionId,
		Operation: functionGenKeyAsym,
		Label:     fmt.Sprintf("%s;%s", pubLabel, privLabel),
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := client.Post(fmt.Sprintf("https://%s/api/hsm/request", serverIP), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	var res ServiceResponse
	err = json.Unmarshal(body, &res)
	if err != nil {
		return err
	}

	if !res.Success {
		if res.ErrorMsg != "" {
			return errors.New(res.ErrorMsg)
		}
		return errors.New("return genkey request is false")
	}
	if res.Data.RetCode != success {
		return errors.New(getReturnCodeMessage(res.Data.RetCode))
	}

	return nil
}

func operationSetIV(client *http.Client, sessionId string, serverIP string, data []byte) error {
	var err error

	payload := ServiceRequest{
		SessionID: sessionId,
		Operation: functionSetIV,
		Data:      data,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := client.Post(fmt.Sprintf("https://%s/api/hsm/request", serverIP), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	var res ServiceResponse
	err = json.Unmarshal(body, &res)
	if err != nil {
		return err
	}

	if !res.Success {
		if res.ErrorMsg != "" {
			return errors.New(res.ErrorMsg)
		}
		return errors.New("return set iv request is false")
	}
	if res.Data.RetCode != success {
		return errors.New(getReturnCodeMessage(res.Data.RetCode))
	}

	return nil
}

func operationChangePIN(client *http.Client, sessionId string, serverIP string, oldPIN string, newPIN string) ([]byte, error) {
	var err error

	payload := ServiceRequest{
		SessionID: sessionId,
		Operation: functionChangePIN,
		Label:     oldPIN,
		Data:      []byte(newPIN),
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	resp, err := client.Post(fmt.Sprintf("https://%s/api/hsm/request", serverIP), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	var res ServiceResponse
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, err
	}

	if !res.Success {
		if res.ErrorMsg != "" {
			return nil, errors.New(res.ErrorMsg)
		}
		return nil, errors.New("return changepin request is false")
	}
	if res.Data.RetCode != success {
		return nil, errors.New(getReturnCodeMessage(res.Data.RetCode))
	}

	apikey, err := base64.StdEncoding.DecodeString(res.Data.Message)
	if err != nil {
		return nil, err
	}

	return apikey, nil
}

func operationChangeLabel(client *http.Client, sessionId string, serverIP string, keyLabel string, newLabel string) error {
	var err error

	payload := ServiceRequest{
		SessionID: sessionId,
		Operation: functionChangeLabel,
		Label:     keyLabel,
		Data:      []byte(newLabel),
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	resp, err := client.Post(fmt.Sprintf("https://%s/api/hsm/request", serverIP), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	var res ServiceResponse
	err = json.Unmarshal(body, &res)
	if err != nil {
		return err
	}

	if !res.Success {
		if res.ErrorMsg != "" {
			return errors.New(res.ErrorMsg)
		}
		return errors.New("return changepin request is false")
	}
	if res.Data.RetCode != success {
		return errors.New(getReturnCodeMessage(res.Data.RetCode))
	}

	return nil
}

func operationGetPub(client *http.Client, sessionId string, serverIP string, pubLabel string) ([]byte, error) {
	var err error

	payload := ServiceRequest{
		SessionID: sessionId,
		Operation: functionGetPub,
		Label:     pubLabel,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	resp, err := client.Post(fmt.Sprintf("https://%s/api/hsm/request", serverIP), "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned status %d", resp.StatusCode)
	}

	var res ServiceResponse
	err = json.Unmarshal(body, &res)
	if err != nil {
		return nil, err
	}

	if !res.Success {
		if res.ErrorMsg != "" {
			return nil, errors.New(res.ErrorMsg)
		}
		return nil, errors.New("return changepin request is false")
	}
	if res.Data.RetCode != success {
		return nil, errors.New(getReturnCodeMessage(res.Data.RetCode))
	}

	pubkey, err := base64.StdEncoding.DecodeString(res.Data.Message)
	if err != nil {
		return nil, err
	}

	return pubkey, nil
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
