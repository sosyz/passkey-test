package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

func BeginRegistration(w http.ResponseWriter, r *http.Request) {
	options, session, err := webAuthn.BeginRegistration(loginUser)
	if err != nil {
		http.Error(w, "Registration failed", http.StatusInternalServerError)
		log.Printf("Begin registration error: %v", err)
		return
	}

	tb := true
	options.Response.AuthenticatorSelection = protocol.AuthenticatorSelection{
		RequireResidentKey: &tb,
		UserVerification:   protocol.VerificationRequired,
	}
	options.Response.Parameters = []protocol.CredentialParameter{
		{
			Type:      protocol.CredentialType("public-key"),
			Algorithm: webauthncose.COSEAlgorithmIdentifier(-7), //EC P256
		},
		{
			Type:      protocol.CredentialType("public-key"),
			Algorithm: webauthncose.COSEAlgorithmIdentifier(-257), // RSA
		},
	}
	if session != nil {
		loginUser.SessionData = *session
	}

	log.Println(session)
	log.Printf("Begin Registration - User ID: %v", loginUser.WebAuthnID())
	log.Printf("Session Data: %+v", session)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

func FinishRegistration(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength == 0 {
		http.Error(w, "Empty request body", http.StatusBadRequest)
		log.Printf("Finish registration error: empty request body")
		return
	}

	credential, err := webAuthn.FinishRegistration(loginUser, loginUser.SessionData, r)
	if err != nil {
		http.Error(w, "Registration verification failed", http.StatusBadRequest)
		log.Printf("Finish registration error: %v", err)
		return
	}
	loginUser.AddCredential(*credential)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode("Registration Success")
}

func BeginLogin(w http.ResponseWriter, r *http.Request) {
	options, session, err := webAuthn.BeginLogin(loginUser)
	if err != nil {
		// Handle Error and return.
		fmt.Println(err)
		return
	}
	options.Response.UserVerification = protocol.VerificationRequired
	// store the session values
	loginUser.SessionData = *session

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
	// options.publicKey contain our registration options
}

func FinishLogin(w http.ResponseWriter, r *http.Request) {
	// Get the session data stored from the function above

	credential, err := webAuthn.FinishLogin(loginUser, loginUser.SessionData, r)
	if err != nil {
		// Handle Error and return.

		return
	}

	// Handle credential.Authenticator.CloneWarning

	// If login was successful, update the credential object
	// Pseudocode to update the user credential.
	loginUser.AddCredential(*credential)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode("Login Success")
}
