package ksema

type Data struct {
	Message string `json:"message"`
	RetCode int    `json:"retCode"`
}

type AuthRequest struct {
	Passkey string `json:"passKey"`
	APIKey  string `json:"apiKey"`
	PIN     string `json:"pin"`
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
	DEFAULT_RANDOM_LEN = 32
	USER_OBJECT        = 2

	FAILED           = 0
	SUCCESS          = 1
	NOLABELFOUND     = 2
	MAXUSAGE         = 3
	UNAUTHORIZEDFUNC = 4
	INVALIDPACKET    = 5
	KEYEXISTED       = 6
	PININCORRECT     = 7
	PINLOCKED        = 8
	SESSIONINVALID   = 9
	INVALIDENCRYPTED = 10
)

const (
	FunctionPing       = "PING"
	FunctionEncrypt    = "ENCRYPT"
	FunctionDecrypt    = "DECRYPT"
	FunctionSign       = "SIGN"
	FunctionVerify     = "VERIFY"
	FunctionRNG        = "RNG"
	FunctionBackup     = "BACKUP"
	FunctionRestore    = "RESTORE"
	FunctionDelete     = "DELETE"
	FunctionGenKeySym  = "GENKEYSYM"
	FunctionGenKeyAsym = "GENKEYASYM"
	FunctionSetIV      = "SETIV"
)

var mapRetCodeToString map[int]string = map[int]string{
	FAILED:           "Failure",
	SUCCESS:          "Success",
	NOLABELFOUND:     "No Label Found",
	MAXUSAGE:         "Max Usage",
	UNAUTHORIZEDFUNC: "Unauthorized Function",
	INVALIDPACKET:    "Invalid Packet",
	KEYEXISTED:       "Key Already Existed",
	PININCORRECT:     "PIN Incorrect",
	PINLOCKED:        "PIN Locked",
	SESSIONINVALID:   "Session Invalid",
	INVALIDENCRYPTED: "Invalid Encrypted Data",
}
