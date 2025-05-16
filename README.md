# ksema-sdk

This is repository for Ksema Client SDK Golang

### Requirement
Golang 1.24

### How to Use
Run command <b>go get github.com/carakacloud/ksema-sdk-go</b> in your golang folder

## Functions
#### func New
```go
func New(serverIP string, apiKey string, pin string) (*Ksema, error)
```
Setup connection to Ksema server with apikey (include pin if user slot).

#### func (*Ksema) Ping
```go
func (*Ksema) Ping() error
```
Request ping to Ksema server.

#### func (*Ksema) Encrypt
```go
func (*Ksema) Encrypt(plainText []byte, keyLabel string) (string, error)
```
Request encryption to Ksema server.

#### func (*Ksema) Decrypt
```go
func (*Ksema) Decrypt(cihperText string, keyLabel string) (string, error)
```
Request decryption to Ksema server.

#### func (*Ksema) Sign
```go
func (*Ksema) Sign(dataFilename string, keyLabel string) (string, error)
```
Request signature to Ksema server.

#### func (*Ksema) Verify
```go
func (*Ksema) Verify(dataFilename string, signatureFilename string, keyLabel string) error
```
Request data verify to Ksema server with signature.

#### func (*Ksema) Random
```go
func (*Ksema) Random(length uint) ([]byte, error)
```
Request random data to Ksema server. If length is not specified (0), it will use DEFAULT_RANDOM_LENGTH (32).

#### func (*Ksema) Backup
```go
func (*Ksema) Backup(filename string, keyLabel string) error
```
Perform backup of requested key to Ksema server.
Return a file backup

#### func (*Ksema) Restore
```go
func (*Ksema) Restore(filename string) error
```
Restore a key with a backed-up file.

#### func (*Ksema) Delete
```go
func (*Ksema) Delete(keyLabel string) error
```
Request key deletion to Ksema server.

#### func (*Ksema) GenKey
```go
func (*Ksema) GenKey(keyLabel1 string, keyLabel2 string) error
```
Request key generation to Ksema server. If keyLabel2 is not empty, it will create a key pair.

#### func (*Ksema) SetIV
```go
func (*Ksema) SetIV(iv string) error
```
Override IV of current connection to Ksema server.
The IV will returned to default IV for the next new connection.
<br>IV must be 16 characters

## Privileges
#### User Object
User object use public key slot shared with other user object. User type Fighter and Contra in consider as user object.<br>
For Fighter, it can only use encrypt, decrypt, random and backup<br>
For Contra, it can only use encrypt, decrypt, sign, verify, random and backup<br><br>
NOTE : *User object is limited to one key (one keypair for Contra) and does not need to specify key label used.*

#### User Slot
User slot use pre-generated key slot. User type Platoon, Battalion and Brigade is consider as user slot.<br>
All user slot can use all ksema operations.<br><br>
NOTE : *User slot have limited key object for different type of user.*

## Example
#### Setup new connection
```go
user, err := ksema.New("103.12.21.237", "00ca6c72486e5652784339367a74fcbcd86668f21a8ac2a07c5c36ba", "ba3030303030303032354c2ff2b074bd39636464633435323830313863653336", "12345678")
if err != nil || user == nil {
	fmt.Printf("error : %v\n", err)
	return
}
```

#### Requesting operation
```go
//For ping
if err := user.Ping(); err != nil {
    fmt.Printf("error : %v\n", err)
} else {
    fmt.Println("server is healthy")
}
```
```go
//Create new key
if err := user.GenKey("AES01", ""); err != nil {
    fmt.Printf("error : %v\n", err)
} else {
    fmt.Println("Key created")
}
//Creating new keypair
if err := user.GenKey("PUB01", "PRIV01"); err != nil {
    fmt.Printf("error : %v\n", err)
} else {
    fmt.Println("Key created")
}
```
```go
//Encryption and decryption
cipher, err := user.Encrypt([]byte("plain text"), "AES01")
if err != nil {
    fmt.Printf("error : %v\n", err)
    return
}
if cipher != nil {
    plain, err := user.Decrypt(cipher, "AES01")
    if err != nil {
        fmt.Printf("error : %v\n", err)
        return
    }

    fmt.Printf("decrypted plain : %s\n", plain)
}
```
```go
//Trying to decrypt with different IV, should be fail
if err := user.SetIV("1234567890123456"); err != nil {
    fmt.Printf("error : %v\n", err)
    return
}
plain, err := user.Decrypt(cipher, "AES01")
if err != nil {
    fmt.Printf("error : %v\n", err)
    return
}

fmt.Printf("decrypted plain : %s\n", plain)
```
```go
//Signing and Verifying
sign, err := user.Sign([]byte("data for sign"), "")
if err != nil {
    fmt.Printf("error : %v\n", err)
}
if sign != nil {
    err := user.Verify([]byte("test sign"), sign, "")
    if err != nil {
        fmt.Printf("error : %v\n", err)
    } else {
        fmt.Println("data is valid")
    }
}
```
```go
//Generating random data
rnd, err := user.Random(10)
if err != nil {
    fmt.Printf("error : %v\n", err)
} else {
    fmt.Printf("random : %s\n", rnd)
    fmt.Printf("len random : %d\n", len(rnd))
}
```
```go
//Request key backup, should return a file
if err := user.Backup("jkk1.key", "AES01"); err != nil {
    fmt.Printf("error : %v\n", err)
} else {
    fmt.Println("Key backed up")
}

//Request key restore with file from key backup
if err := user.Restore("jkk1.key"); err != nil {
    fmt.Printf("error : %v\n", err)
} else {
    fmt.Println("Key restored")
}
```
```go
//Delete a key
if err := user.Delete("AES01"); err != nil {
    fmt.Printf("error : %v\n", err)
} else {
    fmt.Println("Key deleted")
}
```