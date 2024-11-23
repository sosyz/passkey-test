package main

import (
	"bytes"
	"fmt"
	"log"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
)

func Ptr[T any](v T) *T {
	return &v
}

func BeginRegistration(w http.ResponseWriter, r *http.Request) (any, error) {
	// 检查是否已经有注册的凭证
	if len(loginUser.Credentials) > 0 {
		return nil, fmt.Errorf("user already has registered credentials")
	}

	options, session, err := webAuthn.BeginRegistration(loginUser)
	if err != nil {
		return nil, err
	}

	// 设置认证器选项
	options.Response.AuthenticatorSelection = protocol.AuthenticatorSelection{
		RequireResidentKey:      Ptr(true),
		ResidentKey:             protocol.ResidentKeyRequirementRequired,
		UserVerification:        protocol.VerificationRequired,
		AuthenticatorAttachment: protocol.Platform,
	}

	// 设置支持的算法
	options.Response.Parameters = []protocol.CredentialParameter{
		{
			Type:      protocol.CredentialType("public-key"),
			Algorithm: webauthncose.COSEAlgorithmIdentifier(-7), // ES256
		},
		{
			Type:      protocol.CredentialType("public-key"),
			Algorithm: webauthncose.COSEAlgorithmIdentifier(-257), // RS256
		},
	}

	if session != nil {
		loginUser.SessionData = *session
	}

	log.Printf("Begin Registration - User ID: %v", loginUser.WebAuthnID())
	log.Printf("Session Data: %+v", session)

	return options, nil
}

func FinishRegistration(w http.ResponseWriter, r *http.Request) (any, error) {
	if r.ContentLength == 0 {
		return nil, fmt.Errorf("no credential data provided")
	}

	credential, err := webAuthn.FinishRegistration(loginUser, loginUser.SessionData, r)
	if err != nil {
		return nil, err
	}

	// 检查凭证是否已存在
	for _, cred := range loginUser.Credentials {
		if bytes.Equal(cred.ID, credential.ID) {
			return nil, fmt.Errorf("credential already registered")
		}
	}

	loginUser.AddCredential(*credential)
	log.Printf("Registration successful for user %s", loginUser.WebAuthnDisplayName())

	return map[string]string{
		"status":  "success",
		"message": "Registration successful",
	}, nil
}

func BeginLogin(w http.ResponseWriter, r *http.Request) (any, error) {
	options, session, err := webAuthn.BeginDiscoverableLogin()
	if err != nil {
		return nil, fmt.Errorf("login initialization failed: %w", err)
	}

	loginUser.SessionData = *session

	return options, nil
}

func FinishLogin(w http.ResponseWriter, r *http.Request) (any, error) {
	if r.ContentLength == 0 {
		return nil, fmt.Errorf("empty request body")
	}

	credential, err := webAuthn.FinishDiscoverableLogin(func(rawID, userHandle []byte) (user webauthn.User, err error) {
		return loginUser, nil
	}, loginUser.SessionData, r)
	if err != nil {
		return nil, fmt.Errorf("login verification failed: %w", err)
	}

	// 检查克隆警告
	if credential.Authenticator.CloneWarning {
		log.Printf("Warning: Possible cloned authenticator detected for user %s",
			loginUser.WebAuthnDisplayName())
	}

	// 更新凭证
	for i, cred := range loginUser.Credentials {
		if bytes.Equal(cred.ID, credential.ID) {
			loginUser.Credentials[i] = *credential
			break
		}
	}

	log.Printf("Login successful for user %s", loginUser.WebAuthnDisplayName())

	return map[string]string{
		"status":  "success",
		"message": "Login successful",
	}, nil
}
