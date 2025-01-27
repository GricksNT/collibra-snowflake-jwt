# Snowflake Authentication Using JWT in Collibra Workflows

## Overview
This repository contains a Groovy-based solution to authenticate and connect to Snowflake using JWT (JSON Web Tokens) from a Collibra workflow. It was developed to overcome the limitations of the Collibra environment, which does not allow the installation of external libraries.

## Why This Solution Was Developed

When integrating Collibra workflows with Snowflake, the recommended approach for authentication involves key-pair authentication. While Snowflake provides examples in Python, Java, and Node.js, Collibra uses Groovy to develop workflows and restricts the use of external libraries. This posed the following challenges:

1. **Limited Libraries**: The Collibra instance only allows basic imports from Java standard libraries.
2. **Custom JWT Generation**: There was no existing library or direct support for generating JWT tokens in the Collibra environment.

This script was developed to address these challenges, enabling seamless authentication with Snowflake directly from Collibra workflows.

## Features
- **Key-Pair Authentication**: Implements RSA-based key-pair signing for JWT tokens.
- **Customizable Payload**: Generates tokens with customizable claims, including `iss`, `sub`, `iat`, and `exp`.
- **Key Formatting**: Formats private and public keys for compatibility.
- **Reusable Design**: Easily integrates into multiple workflows for data extraction and loading.

## Implementation

### Key Classes and Methods

1. **`JWTGenerator` Class**
   - Manages JWT creation and lifecycle.
   - Automatically renews tokens based on a defined delay.

2. **Key Loading Methods**
   - `loadPrivateKey`: Reads and parses the private key in PKCS8 format.
   - `loadPublicKey`: Reads and parses the public key in X509 format.

3. **Token Generation**
   - Uses `java.security.Signature` to sign the JWT header and payload.
   - Encodes the header, payload, and signature into a final JWT.

4. **Utility Functions**
   - `prepareAccountNameForJwt`: Formats account identifiers for compatibility with Snowflake.
   - `calculatePublicKeyFingerprint`: Computes a SHA-256 fingerprint of the public key for identification.

### Code Example
Here is the main flow of the script:

```groovy
// Initialize the JWT generator with account details and keys
def account = "example.snowflakecomputing.com"
def user = "user@example.com"
def tokenGenerator = new JWTGenerator(account, user, privateKeyContents, publicKeyContents)

// Generate the token and use it for authentication
def jwtToken = tokenGenerator.getToken()
loggerApi.info('Generated JWT Token: ' + jwtToken)
```

### Dependencies
The script only uses the following Java standard libraries:
- `java.security`
- `java.util.Base64`
- `java.time.Instant`

### How to Use

1. **Provide Keys**:
   - Add your RSA private and public keys in the correct PEM format.
   - The script includes a `formatKey` method to handle key formatting.

2. **Configure Account Details**:
   - Update `account` and `user` with your Snowflake account identifier and user name.

3. **Run the Workflow**:
   - Integrate the script into your Collibra workflow and execute it.

### Key Formatting Example
Ensure keys are in the following format before passing them to the script:

#### Private Key
```
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD...
-----END PRIVATE KEY-----
```

#### Public Key
```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQE...
-----END PUBLIC KEY-----
```

## Applications

With this solution, Collibra workflows can:
- Load data into Snowflake tables.
- Extract data from Snowflake for processing in Collibra.
- Automate workflows requiring secure communication with Snowflake.

## Limitations
- **Key Management**: Ensure keys are securely stored and managed.
- **Hardcoded Values**: Some values, like token lifetime, may need adjustment for specific use cases.

## Contributions
Feel free to submit pull requests or issues for improvements or feature requests.

## License
This project is licensed under the MIT License. See `LICENSE` for details.
=======
# collibra-snowflake-jwt
This repository contains a Groovy-based solution to authenticate and integrate Collibra workflows with Snowflake using JWT (JSON Web Tokens).  
![image](https://github.com/user-attachments/assets/91c7a5b7-3363-4242-92a6-c3ec3b6fbfd9)
![image](https://github.com/user-attachments/assets/2e17b331-c82a-47bb-858e-5fc49e14636a)
![image](https://github.com/user-attachments/assets/49b54663-1f37-4353-a938-699cce8604ad)



