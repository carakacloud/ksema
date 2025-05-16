# KSEMA

Ksema adalah layanan Managed Hardware Security Module (HSM) yang berjalan di atas infrastruktur cloud Equnix yang profesional dan diandalkan banyak perusahaan. Dengan Ksema, Anda mampu menjalankan operasi kriptografi dengan infrastruktur bersertifikasi FIPS 140-2 Level 3 tanpa repot mengelola hardware fisik sendiri.

Minimum Golang Version: **1.24**

## Installation
```bash
go get github.com/carakacloud/ksema
```

## Usage
```go
package main

import (
	"log"
	"os"

	"github.com/carakacloud/ksema"
)

func main() {
	ksemaServerIp := os.Getenv("KSEMA_HOST")
	ksemaAPIKey := os.Getenv("KSEMA_API_KEY")
	ksemaPIN := os.Getenv("KSEMA_PIN")

	user, err := ksema.New(ksemaServerIp, ksemaAPIKey, ksemaPIN)
	if err != nil {
		log.Fatal("Error creating Ksema object")
	}

	if err := user.Ping(); err != nil {
		log.Fatal("Failed to ping server")
	}

	message := []byte("Hello, this is a secret message!")

	encrypted, err := user.Encrypt(message, "")
	if err != nil {
		log.Fatal("Failed to encrypt")
	}
	log.Printf("Encrypted: %s\n", encrypted)

	decrypted, err := user.Decrypt(encrypted, "")
	if err != nil {
		log.Fatal("Failed to decrypt")
	}
	log.Printf("Decrypted: %s\n", decrypted)
}
```