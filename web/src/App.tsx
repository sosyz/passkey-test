import "./App.css";
import { useState } from "react";

function App() {
    if (!navigator.credentials) {
        alert("WebAuthn is not supported");
    }

    const [isPasskeySupported, setIsPasskeySupported] = useState(false);
    const [isLoggingIn, setIsLoggingIn] = useState(false);
    const [isCreating, setIsCreating] = useState(false);
    if (
        window.PublicKeyCredential &&
        PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable &&
        PublicKeyCredential.isConditionalMediationAvailable
    ) {
        console.log("Passkey is supported");

        // Check if user verifying platform authenticator is available.
        Promise.all([
            PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(),
            PublicKeyCredential.isConditionalMediationAvailable(),
        ]).then((results) => {
            if (results.every((r) => r === true)) {
                setIsPasskeySupported(true);
            }
        });
    }

    const host = "http://localhost:8080";
    interface Credential {
        id: string;
        type: string;
    }

    const createPasskey = async () => {
        if (isCreating) return;

        try {
            setIsCreating(true);
            const response = await fetch(`${host}/begin-registration`);
            if (!response.ok) {
                throw new Error("Registration failed");
            }
            const data = await response.json();

            data.publicKey.challenge = base64ToBuffer(data.publicKey.challenge);
            if (data.publicKey.user?.id) {
                data.publicKey.user.id = base64ToBuffer(data.publicKey.user.id);
            }

            const credential = (await navigator.credentials.create({
                publicKey: data.publicKey,
            })) as PublicKeyCredential;

            if (!credential) {
                throw new Error("Credential is null, please try again");
            }

            const credentialResponse =
                credential.response as AuthenticatorAttestationResponse;
            const finishResponse = await fetch(`${host}/finish-registration`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({
                    id: credential.id,
                    type: credential.type,
                    rawId: bufferToBase64(credential.rawId),
                    response: {
                        clientDataJSON: bufferToBase64(
                            credentialResponse.clientDataJSON
                        ),
                        attestationObject: bufferToBase64(
                            credentialResponse.attestationObject
                        ),
                    },
                }),
            });

            console.log(finishResponse);

            const finishData = await finishResponse.json();
            console.log(finishData);
            alert("Registration Success");
        } catch (error) {
            if (error instanceof TypeError) {
                alert(error.name + ": " + error.message);
            } else {
                console.error("Registration error:", error);
            }
        } finally {
            setIsCreating(false);
        }
    };

    const loginWithPasskey = async () => {
        if (isLoggingIn) {
            return;
        }

        try {
            setIsLoggingIn(true);
            const response = await fetch(`${host}/begin-login`);
            const data = await response.json();

            const publicKey = {
                challenge: base64ToBuffer(data.publicKey.challenge),
                rpId: data.publicKey.rpId,
                allowCredentials: data.publicKey.allowCredentials?.map(
                    (cred: Credential) => ({
                        type: cred.type,
                        id: base64ToBuffer(cred.id),
                    })
                ),
                userVerification: "preferred",
            } as PublicKeyCredentialRequestOptions;
            console.log(publicKey);

            const abortController = new AbortController();
            const credential = (await navigator.credentials.get({
                publicKey: publicKey,
                signal: abortController.signal,
                mediation: "conditional",
            })) as PublicKeyCredential;

            if (!credential) {
                throw new Error("Credential is null, please try again");
            }
            console.log(credential);

            // 构建可序列化的凭证对象
            const credentialResponse =
                credential.response as AuthenticatorAssertionResponse;
            const credentialJSON = {
                id: credential.id,
                type: credential.type,
                rawId: bufferToBase64(credential.rawId),
                response: {
                    clientDataJSON: bufferToBase64(
                        credentialResponse.clientDataJSON
                    ),
                    authenticatorData: bufferToBase64(
                        credentialResponse.authenticatorData
                    ),
                    signature: bufferToBase64(credentialResponse.signature),
                    userHandle: credentialResponse.userHandle
                        ? bufferToBase64(credentialResponse.userHandle)
                        : null,
                    authenticatorAttachment: credential.authenticatorAttachment,
                },
            };

            const finishResponse = await fetch(`${host}/finish-login`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify(credentialJSON),
            });
            console.log(finishResponse);

            const finishData = await finishResponse.json();
            console.log(finishData);

            alert("Login Success");
        } catch (error) {
            console.error("Login error:", error);
        } finally {
            setIsLoggingIn(false);
        }
    };

    return (
        <>
            <h1>Passkey Authentication Test</h1>
            <div>
                <label htmlFor="username">Username</label>
                <input
                    type="text"
                    id="username"
                    autoComplete="username webauthn"
                />
                {isPasskeySupported && (
                    <button onClick={createPasskey}>
                        Create a new passkey
                    </button>
                )}
                {isPasskeySupported && (
                    <button onClick={loginWithPasskey} disabled={isLoggingIn}>
                        {isLoggingIn ? "Logging in..." : "Login with passkey"}
                    </button>
                )}
                {!isPasskeySupported && <p>Passkey is not supported</p>}
            </div>
        </>
    );
}

// 添加辅助函数来转换 base64 到 ArrayBuffer
function base64ToBuffer(base64: string): ArrayBuffer {
    // 替换 URL 安全的 base64 字符
    const b64 = base64.replace(/-/g, "+").replace(/_/g, "/");
    // 添加填充
    const padding = "=".repeat((4 - (b64.length % 4)) % 4);
    const base64String = b64 + padding;

    const binaryString = window.atob(base64String);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

// 添加 bufferToBase64 辅助函数
function bufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    const base64 = window.btoa(binary);
    // 转换为 URL 安全的 base64
    return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

export default App;
