// https://developers.google.com/identity/passkeys?hl=zh-cn

package main

import (
	"crypto/rand"
	"fmt"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type User struct {
	ID          []byte // 添加用户唯一标识
	DisplayName string // 添加显示名
	SessionData webauthn.SessionData
	Credentials []webauthn.Credential // 改为切片存储多个凭证
}

func (u User) WebAuthnID() []byte {
	return u.ID
}

func (u User) WebAuthnName() string {
	return "root"
}

func (u User) WebAuthnDisplayName() string {
	if u.DisplayName == "" {
		return u.WebAuthnName()
	}
	return u.DisplayName
}

func (u User) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

// 添加一个新方法用于添加凭证
func (u *User) AddCredential(cred webauthn.Credential) {
	if u.Credentials == nil {
		u.Credentials = make([]webauthn.Credential, 0)
	}
	u.Credentials = append(u.Credentials, cred)
}

var (
	webAuthn  *webauthn.WebAuthn
	err       error
	loginUser User = User{
		DisplayName: "管理员",
	}
)

func setupCORS(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 设置 CORS 头
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		// 处理 OPTIONS 预检请求
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		handler(w, r)
	}
}

func main() {
	wconfig := &webauthn.Config{
		RPDisplayName: "Answer",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost", "http://localhost"},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationPreferred,
		},
		AttestationPreference: protocol.PreferDirectAttestation,
	}

	buf := make([]byte, 32)
	rand.Read(buf)
	loginUser.ID = buf

	if webAuthn, err = webauthn.New(wconfig); err != nil {
		fmt.Println(err)
	}

	http.HandleFunc("/begin-registration", setupCORS(BeginRegistration))
	http.HandleFunc("/finish-registration", setupCORS(FinishRegistration))
	http.HandleFunc("/begin-login", setupCORS(BeginLogin))
	http.HandleFunc("/finish-login", setupCORS(FinishLogin))

	if err := http.ListenAndServe(":8080", nil); err != nil {
		panic(err)
	}
}
