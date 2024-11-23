// https://developers.google.com/identity/passkeys?hl=zh-cn

package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type User struct {
	ID          []byte // 添加用户唯一标识
	DisplayName string // 添加显示名
	SessionData webauthn.SessionData
	Credentials []webauthn.Credential
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

type handlerFunc func(http.ResponseWriter, *http.Request) (any, error)

func handleMiddle(handler handlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 设置 CORS 头
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:5173")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		// 处理 OPTIONS 预检请求
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		resp, err := handler(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if resp != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		}
	}
}

func main() {
	wconfig := &webauthn.Config{
		RPDisplayName: "Answer",
		RPID:          "localhost",
		RPOrigins:     []string{"http://localhost:5173"},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:             protocol.ResidentKeyRequirementRequired,
			UserVerification:        protocol.VerificationRequired,
			AuthenticatorAttachment: protocol.Platform,
		},
		Timeouts: webauthn.TimeoutsConfig{
			Login: webauthn.TimeoutConfig{
				Timeout: 300 * time.Second,
			},
			Registration: webauthn.TimeoutConfig{
				Timeout: 300 * time.Second,
			},
		},
		AttestationPreference: protocol.PreferDirectAttestation,
	}

	buf := make([]byte, 32)
	rand.Read(buf)
	loginUser.ID = buf

	if webAuthn, err = webauthn.New(wconfig); err != nil {
		fmt.Println(err)
	}

	router := map[string]handlerFunc{
		"/begin-registration":  BeginRegistration,
		"/finish-registration": FinishRegistration,
		"/begin-login":         BeginLogin,
		"/finish-login":        FinishLogin,
	}
	for path, handler := range router {
		http.HandleFunc(path, handleMiddle(handler))
	}

	if err := http.ListenAndServe(":8080", nil); err != nil {
		panic(err)
	}
}
