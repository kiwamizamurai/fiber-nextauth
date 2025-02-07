# NextAuth.js and Go Backend JWT Flow

## Sequence Diagram

```mermaid
sequenceDiagram
    participant Client
    participant NextAuth
    participant Go Backend

    Note over NextAuth: JWT Encode Process
    NextAuth->>NextAuth: 1. HKDF Key Derivation
    Note over NextAuth: secret[0] + salt + info<br>↓<br>encryptionSecret

    NextAuth->>NextAuth: 2. Calculate JWK Thumbprint
    Note over NextAuth: encryptionSecret<br>↓<br>kid

    NextAuth->>NextAuth: 3. JWE Encryption
    Note over NextAuth: header: {alg: "dir", enc: "A256CBC-HS512", kid}<br>payload: {name, email, exp, iat, jti}<br>↓<br>A256CBC-HS512

    NextAuth->>Client: 4. Set-Cookie
    Note over Client: Cookie: authjs.session-token=<encrypted>

    Client->>Go Backend: 5. Request
    Note over Client: Cookie or Authorization: Bearer

    Go Backend->>Go Backend: 6. Token Extraction
    Note over Go Backend: Cookie/Header → token

    Go Backend->>Go Backend: 7. HKDF Key Derivation
    Note over Go Backend: secrets[] + salt + info

    Go Backend->>Go Backend: 8. JWE Decryption
    Note over Go Backend: kid matching and decrypt
```

## Technical Details

### Key ID (kid) Matching Process

The `kid` matching process is a crucial security mechanism in the JWT validation flow between NextAuth.js and the Go backend. Here's how it works:

1. **Token Header Parsing**
   - The JWE token is split into its components
   - The header is base64-decoded and parsed
   - Contains critical information: `kid` (Key ID), `enc` (Encryption Algorithm), `alg` (Key Management Algorithm)

2. **Key Derivation**
   - Both NextAuth.js and Go backend use HKDF (HMAC-based Key Derivation Function)
   - Components:
     - Secret: The shared NEXTAUTH_SECRET
     - Salt: Cookie name ("authjs.session-token")
     - Info: "Auth.js Generated Encryption Key"
   - Output: A symmetric key for A256CBC-HS512 encryption (64 bytes)

3. **Encryption/Decryption**
   - Algorithm: A256CBC-HS512 (AES-256-CBC with HMAC-SHA-512)
   - Direct key agreement ("dir") means the derived key is used directly
   - The `kid` in the header helps identify which secret was used for key derivation
