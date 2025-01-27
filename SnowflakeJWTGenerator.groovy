import java.security.PrivateKey
import java.security.PublicKey
import java.security.KeyFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.security.Signature
import java.security.MessageDigest
import java.time.Instant
import java.util.Base64

def ISSUER = "iss"
def EXPIRE_TIME = "exp"
def ISSUE_TIME = "iat"
def SUBJECT = "sub"

class JWTGenerator {
    def LIFETIME = 59 * 60 * 1000 // in milliseconds
    def RENEWAL_DELTA = 54 * 60 * 1000 // in milliseconds
    def account, user, qualifiedUsername, lifetime, renewalDelay, privateKey, publicKey, renewTime, token

    JWTGenerator(account, user, privateKeyContents, publicKeyContents) {
        this.account = prepareAccountNameForJwt(account)
        this.user = user.toUpperCase()
        this.qualifiedUsername = "${this.account}.${this.user}"
        this.lifetime = LIFETIME
        this.renewalDelay = RENEWAL_DELTA
        this.privateKey = loadPrivateKey(privateKeyContents)
        this.publicKey = loadPublicKey(publicKeyContents)
        this.renewTime = Instant.now()
        this.token = null
    }

    def loadPrivateKey(privateKeyContents) {
        def keyBytes = Base64.getDecoder().decode(privateKeyContents.replaceAll("\\n", "").replaceAll("-----BEGIN PRIVATE KEY-----", "").replaceAll("-----END PRIVATE KEY-----", ""))
        def spec = new PKCS8EncodedKeySpec(keyBytes)
        def kf = KeyFactory.getInstance("RSA")
        return kf.generatePrivate(spec)
    }

    def loadPublicKey(publicKeyContents) {
        def keyBytes = Base64.getDecoder().decode(publicKeyContents.replaceAll("\\n", "").replaceAll("-----BEGIN PUBLIC KEY-----", "").replaceAll("-----END PUBLIC KEY-----", ""))
        def spec = new X509EncodedKeySpec(keyBytes)
        def kf = KeyFactory.getInstance("RSA")
        return kf.generatePublic(spec)
    }

    def prepareAccountNameForJwt(rawAccount) {
        def account = rawAccount
        if (!account.contains('.global')) {
            def idx = account.indexOf('.')
            if (idx > 0) {
                account = account.substring(0, idx)
            }
        } else {
            def idx = account.indexOf('-')
            if (idx > 0) {
                account = account.substring(0, idx)
            }
        }
        return account.toUpperCase()
    }

    def calculatePublicKeyFingerprint(publicKey) {
        def publicKeyBytes = publicKey.getEncoded()
        MessageDigest sha = MessageDigest.getInstance("SHA-256")
        def hash = sha.digest(publicKeyBytes)
        return 'SHA256:' + Base64.getEncoder().encodeToString(hash)
    }

    def getToken() {
        def nowMillis = Instant.now().toEpochMilli() // Keep the timestamp in milliseconds
        if (this.token == null || this.renewTime.isBefore(Instant.now())) {
            this.renewTime = Instant.now().plusMillis(this.renewalDelay)
            def publicKeyFingerprint = calculatePublicKeyFingerprint(this.publicKey)
            def payloadMap = [
    						iss: "${this.qualifiedUsername}.${publicKeyFingerprint}",
    						sub: this.qualifiedUsername,
    						iat: (nowMillis.intdiv(1000)), // Convert to seconds
    						exp: ((nowMillis + this.lifetime).intdiv(1000)) // Convert to seconds
							]
            def headerMap = [alg: "RS256", typ: "JWT"]
            def headerJsonString = groovy.json.JsonOutput.toJson(headerMap)
            def payloadJsonString = groovy.json.JsonOutput.toJson(payloadMap)
            def encodedHeaderString = Base64.getUrlEncoder().withoutPadding().encodeToString(headerJsonString.getBytes("UTF-8"))
            def encodedPayloadString = Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJsonString.getBytes("UTF-8"))
            def signatureInputString = "${encodedHeaderString}.${encodedPayloadString}"
            def signatureBytes = signData(signatureInputString.getBytes("UTF-8"), this.privateKey)
            def encodedSignatureString = Base64.getUrlEncoder().withoutPadding().encodeToString(signatureBytes)

            this.token = "${signatureInputString}.${encodedSignatureString}"
        }

        return this.token
    }

    private byte[] signData(byte[] data, PrivateKey key) {
        try {
            Signature signatureInstance = Signature.getInstance("SHA256withRSA")
            signatureInstance.initSign(key)
            signatureInstance.update(data)
            return signatureInstance.sign()
        } catch (Exception e) {
            throw new RuntimeException("Failed to calculate hmac-sha256", e)
        }
    }
}


def formatKey(key, keyType) {
    // Replace spaces with line breaks
    def formattedKey = key.replaceAll(" ", "\n")

    // Remove leading and trailing whitespace
    formattedKey = formattedKey.trim()

    // Add BEGIN and END markers with triple quotes for a multi-line string
    def keyMarker = keyType == "public" ? "PUBLIC KEY" : "PRIVATE KEY"
    formattedKey = """
-----BEGIN $keyMarker-----
$formattedKey
-----END $keyMarker-----
"""
    return formattedKey
}


// Store the private key contents in a variable
def privateKeyContents = execution.getVariable("privateKey")
privateKeyContents = formatKey(privateKeyContents, "private")



// Store the public key contents in a variable
def publicKeyContents = execution.getVariable("publicKey")
publicKeyContents= formatKey(publicKeyContents, "public")


def accountIdentifier = execution.getVariable("accountIdentifier")
def userName = execution.getVariable("userName")
def account = "${accountIdentifier}.snowflakecomputing.com"
def user = "${userName}@CMA-CGM.COM"
def tokenGenerator = new JWTGenerator(account, user, privateKeyContents, publicKeyContents)
loggerApi.info('JWT generated: ' +tokenGenerator.getToken())

execution.setVariable('JWT',tokenGenerator.getToken())



