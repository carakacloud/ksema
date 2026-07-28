package ksema

const (
	SHA256_PSS = iota + 1
	SHA512_PSS
	SHA256_PKCS
)

type Data struct {
	Message string `json:"message"`
	RetCode int    `json:"retCode"`
}

type AuthRequest struct {
	APIKey string `json:"apiKey"`
	PIN    string `json:"pin"`
}

type AuthData struct {
	SessionID string `json:"sessionId"`
	UserType  int    `json:"userType"`
}

type AuthResponse struct {
	Success  bool     `json:"success"`
	Data     AuthData `json:"data"`
	ErrorMsg string   `json:"error"`
}

type ServiceRequest struct {
	SessionID string `json:"sessionId"`
	Operation string `json:"operation"`
	Label     string `json:"label"`
	Data      []byte `json:"data"`
}

type ServiceResponse struct {
	Success  bool   `json:"success"`
	Data     Data   `json:"data"`
	ErrorMsg string `json:"error"`
}

const (
	defaultRandomLen = 32
	userObject       = 2

	failed           = 0
	success          = 1
	noLabelFound     = 2
	maxUsage         = 3
	unAuthorizedFunc = 4
	invalidPacket    = 5
	keyExisted       = 6
	pinIncorrect     = 7
	pinLocked        = 8
	sessionInvalid   = 9
	invalidEncrypted = 10
)

const (
	functionPing          = "PING"
	functionEncrypt       = "ENCRYPT"
	functionDecrypt       = "DECRYPT"
	functionSign256PSS    = "SIGN256PSS"
	functionSign512PSS    = "SIGN512PSS"
	functionSign256PKCS   = "SIGN256PKCS"
	functionVerify256PSS  = "VERIFY256PSS"
	functionVerify512PSS  = "VERIFY512PSS"
	functionVerify256PKCS = "VERIFY256PKCS"
	functionRNG           = "RNG"
	functionBackup        = "BACKUP"
	functionRestore       = "RESTORE"
	functionDelete        = "DELETE"
	functionGenKeySym     = "GENKEYSYM"
	functionGenKeyAsym    = "GENKEYASYM"
	functionSetIV         = "SETIV"
	functionChangePIN     = "CHANGEPIN"
	functionChangeLabel   = "CHANGELABEL"
	functionGetPub        = "GETPUB"
)

var mapRetCodeToString map[int]string = map[int]string{
	failed:           "Failure",
	success:          "Success",
	noLabelFound:     "No Label Found",
	maxUsage:         "Max Usage",
	unAuthorizedFunc: "Unauthorized Function",
	invalidPacket:    "Invalid Packet",
	keyExisted:       "Key Already Existed",
	pinIncorrect:     "PIN Incorrect",
	pinLocked:        "PIN Locked",
	sessionInvalid:   "Session Invalid",
	invalidEncrypted: "Invalid Encrypted Data",
}
