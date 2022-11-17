package edu.uky.pml.epic.api;

import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.okhttp.client.OkHttpRestfulClientFactory;
import ca.uhn.fhir.rest.client.api.IGenericClient;
import ca.uhn.fhir.rest.client.interceptor.BearerTokenAuthInterceptor;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.squareup.moshi.JsonAdapter;
import com.squareup.moshi.Moshi;
import okhttp3.*;
import org.apache.commons.codec.binary.Base64;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Wrapper class to add Epic FHIR authentication to HAPI FHIR IGenericClient instantiation
 * @author Caylin Hickey (caylin.hickey@uky.edu)
 */
public class EpicAPI {
    private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(EpicAPI.class);
    private final String epicAPIURLPrefix;
    private final String backendServiceClientID;
    private final String privateKeyFilePath;
    private final String publicCertificateFilePath;

    private String accessToken = null;
    private Date accessTokenExpiration = null;

    private final OkHttpClient client = new OkHttpClient();
    private final Moshi moshi = new Moshi.Builder().build();
    private final JsonAdapter<EpicAccessTokenResponse> accessTokenResponseJsonAdapter =
            moshi.adapter(EpicAccessTokenResponse.class);
    private final FhirContext fhirCtx;

    /**
     * Class to manage requests to Epic AppMarket/FHIR API as a backend service
     * @param epicAPIURLPrefix Prefix URI for the Epic endpoint
     * @param backendServiceClientID Client ID for backend service app
     * @param privateKeyFilePath The file path for the RSA private key used to sign JWT authorization requests
     */
    public EpicAPI(String epicAPIURLPrefix, String backendServiceClientID, String privateKeyFilePath) {
        logger.info("Initializing new EpicAPI instance");
        logger.trace("Adding BouncyCastle provider");
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        this.epicAPIURLPrefix = (epicAPIURLPrefix.endsWith("/")) ?
                epicAPIURLPrefix.substring(0, epicAPIURLPrefix.length() - 1) :
                epicAPIURLPrefix;
        logger.trace("Epic API URL: {}", getEpicAPIURLPrefix());
        this.backendServiceClientID = backendServiceClientID;
        logger.trace("Epic AppMarket Backend Service Client ID: {}", getBackendServiceClientID());
        this.privateKeyFilePath = privateKeyFilePath;
        logger.trace("Using private key: {}", getPrivateKeyFilePath());
        this.publicCertificateFilePath = null;
        logger.trace("Initializing HAPI FHIR R4 context");
        this.fhirCtx = FhirContext.forR4();
        logger.trace("Setting OkHttp as default HAPI FHIR Restful Client");
        this.fhirCtx.setRestfulClientFactory(new OkHttpRestfulClientFactory(this.fhirCtx));
    }

    /**
     * Class to manage requests to Epic AppMarket/FHIR API as a backend service
     * @param epicAPIURLPrefix Prefix URI for the Epic endpoint
     * @param backendServiceClientID Client ID for backend service app
     * @param privateKeyFilePath The file path for the RSA private key used to sign JWT authorization requests
     * @param publicCertificateFilePath The file path for the X.509 public certificate submitted to Epic AppMarket
     *                                  for JWT signature verification
     */
    public EpicAPI(String epicAPIURLPrefix, String backendServiceClientID, String privateKeyFilePath,
                   String publicCertificateFilePath) {
        logger.info("Initializing new EpicAPI instance with JWT validation");
        logger.trace("Adding BouncyCastle provider");
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        this.epicAPIURLPrefix = (epicAPIURLPrefix.endsWith("/")) ?
                epicAPIURLPrefix.substring(0, epicAPIURLPrefix.length() - 1) :
                epicAPIURLPrefix;
        logger.trace("Epic API URL: {}", getEpicAPIURLPrefix());
        this.backendServiceClientID = backendServiceClientID;
        logger.trace("Epic AppMarket Backend Service Client ID: {}", getBackendServiceClientID());
        this.privateKeyFilePath = privateKeyFilePath;
        logger.trace("Using private key: {}", getPrivateKeyFilePath());
        this.publicCertificateFilePath = publicCertificateFilePath;
        logger.trace("Verifying JWT with public certificate file: {}", getPublicCertificateFilePath());
        logger.trace("Initializing HAPI FHIR R4 context");
        this.fhirCtx = FhirContext.forR4();
        logger.trace("Setting OkHttp as default HAPI FHIR Restful Client");
        this.fhirCtx.setRestfulClientFactory(new OkHttpRestfulClientFactory(this.fhirCtx));
    }

    /**
     * Return an authenticated FHIR client to use for API requests
     * @return IGenericClient? An authenticated client or null if authentication fails
     */
    public IGenericClient getFhirClient() {
        logger.info("Building authenticated HAPI FHIR client");
        String accessToken = requestAccessToken();
        if (accessToken == null)
            return null;
        logger.trace("Building BearerToken interceptor for HAPI FHIR client using access token");
        BearerTokenAuthInterceptor authInterceptor = new BearerTokenAuthInterceptor(accessToken);
        logger.trace("Instantiating new HAPI FHIR client from existing R4 context");
        IGenericClient client = fhirCtx.newRestfulGenericClient(getEpicR4EndpointURL());
        logger.trace("Registering BearerToken interceptor with client");
        client.registerInterceptor(authInterceptor);
        return client;
    }

    /**
     * Returns a valid Epic API access token for API requests
     * @return String Epic backend service API access token
     */
    private String requestAccessToken() {
        logger.trace("Access token requested");
        if (getAccessToken() != null)
            return getAccessToken();
        String requestJWT = buildAccessTokenRequestJWT();
        if (requestJWT == null)
            return null;
        RequestBody formBody = new FormBody.Builder()
                .addEncoded("grant_type", "client_credentials")
                .addEncoded("client_assertion_type",
                        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
                .addEncoded("client_assertion", requestJWT)
                .build();
        Request request = new Request.Builder()
                .url(getEpicOAuthTokenURL())
                .post(formBody)
                .build();
        try (Response response = client.newCall(request).execute()) {
            if (response.isSuccessful()) {
                EpicAccessTokenResponse accessTokenResponse = accessTokenResponseJsonAdapter
                        .fromJson(Objects.requireNonNull(response.body()).source());
                if (accessTokenResponse == null) {
                    logger.error("Failed to process authorization server response");
                    return null;
                }
                this.accessToken = accessTokenResponse.access_token;
                this.accessTokenExpiration = new Date(System.currentTimeMillis() +
                        TimeUnit.SECONDS.toMillis(accessTokenResponse.expires_in));
                return getAccessToken();
            } else if (response.code() == 400) {
                EpicAccessTokenResponse accessTokenResponse = accessTokenResponseJsonAdapter
                        .fromJson(Objects.requireNonNull(response.body()).source());
                if (accessTokenResponse == null)
                    logger.error("Failed to process authorization server [{}] response", getEpicOAuthTokenURL());
                else
                    logger.error("Failed to acquire access token from authorization server [{}], error received: {}",
                            getEpicOAuthTokenURL(), accessTokenResponse.error);
                return null;
            } else
                throw new IOException("Unexpected code from Epic authorization server " + response);
        } catch (NullPointerException e) {
            logger.error("Received a null response from the Epic authorization server [{}] using JWT [{}]",
                    getEpicOAuthTokenURL(), requestJWT);
            return null;
        } catch (IOException e) {
            logger.error("Error communicating with Epic authorization server [{}]", getEpicOAuthTokenURL());
            return null;
        }
    }

    /**
     * Builds a signed JWT request used in Epic authorization requests for an access token. If the public key uploaded
     * to Epic's AppMarket has been provided, it will be used to verify the JWT as well.
     * @return A String representing the signed JWT authorization request or null if a failure has occurred.
     */
    private String buildAccessTokenRequestJWT() {
        String token;
        try {
            RSAPrivateKey privateKey = readPrivateKey(getPrivateKeyFilePath());
            Algorithm algorithm = Algorithm.RSA384(null, privateKey);
            String aud = getEpicOAuthTokenURL();
            Date iat = new Date();
            Date exp = new Date(System.currentTimeMillis() + TimeUnit.MINUTES.toMillis(5));
            String jti = UUID.randomUUID().toString();
            token = JWT.create()
                    .withIssuer(getBackendServiceClientID())
                    .withSubject(getBackendServiceClientID())
                    .withAudience(aud)
                    .withJWTId(jti)
                    .withIssuedAt(iat)
                    .withExpiresAt(exp)
                    .withNotBefore(iat)
                    .sign(algorithm);
            if (getPublicCertificateFilePath() != null) {
                RSAPublicKey publicKey = readPublicKey(getPublicCertificateFilePath());
                Algorithm algorithmVerify = Algorithm.RSA384(publicKey, null);
                JWTVerifier verifier = JWT.require(algorithmVerify)
                        .withIssuer(getBackendServiceClientID())
                        .withSubject(getBackendServiceClientID())
                        .withAudience(aud)
                        .withJWTId(jti)
                        .build();
                verifier.verify(token);
                logger.trace("Epic authorization JWT verified successfully");
            }
        } catch (JWTVerificationException e) {
            logger.error("Failed to create Epic access token request JWT: {}", e.getMessage());
            token = null;
        } catch (Exception e) {
            logger.error("buildAccessTokenRequestJWT Exception: {}", e.getMessage());
            logger.error("", e);
            token = null;
        }
        return token;
    }

    /**
     * Reads the PEM-encoded private key file used to sign JWT requests for Epic authorization (see
     * <a href="https://appmarket.epic.com/Article?docId=oauth2&section=Creating-Key-Pair_OpenSSL">Epic AppMarket</a>
     * for details)
     * @param privateKeyPath The filepath to the private key file in PEM format
     * @return RSAPrivateKey instance of the private key file
     * @throws IOException The key file does not exist or cannot be read
     * @throws NoSuchAlgorithmException The required RSA algorithm does not exist
     * @throws InvalidKeySpecException The key is in the wrong format
     */
    private static RSAPrivateKey readPrivateKey(String privateKeyPath) throws IOException, NoSuchAlgorithmException,
            NoSuchProviderException, InvalidKeySpecException {
        String key = new String(Files.readAllBytes(Paths.get(privateKeyPath)), Charset.defaultCharset());
        String privateKeyPEM = key
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "");
        byte[] encoded = Base64.decodeBase64(privateKeyPEM);
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encoded);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
        return (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
    }

    /**
     * Reads the public key associated with the private key used to sign JWT requests for Epic authorization (see
     * <a href="https://appmarket.epic.com/Article?docId=oauth2&section=Creating-Key-Pair_OpenSSL">Epic AppMarket</a>
     * for details)
     * @param publicCertificatePath The filepath to the public certificate file in PEM format
     * @return RSAPublicKey instance of the public key file
     * @throws CertificateException The required X.509 certificate factory does not exist
     * @throws IOException The key file does not exist or cannot be read
     */
    private static RSAPublicKey readPublicKey(String publicCertificatePath) throws CertificateException, IOException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certificateFactory
                .generateCertificate(Files.newInputStream(Paths.get(publicCertificatePath)));
        return (RSAPublicKey) certificate.getPublicKey();
    }

    /**
     * The Epic API root URL to be used for requests
     * @return String Epic API root URL
     */
    public String getEpicAPIURLPrefix() {
        return epicAPIURLPrefix;
    }

    /**
     * Formats the Epic API URL with the standard OAuth2 access endpoint for access token requests
     * @return String Epic API OAuth2 token request endpoint URL
     */
    public String getEpicOAuthTokenURL() {
        return String.format("%s/oauth2/token", getEpicAPIURLPrefix());
    }

    public String getEpicR4EndpointURL() {
        return String.format("%s/api/FHIR/R4", getEpicAPIURLPrefix());
    }

    /**
     * The Epic AppMarket Client ID assigned to the backend service app
     * @return String client id
     */
    public String getBackendServiceClientID() {
        return backendServiceClientID;
    }

    /**
     * The file path for the RSA private key used to sign the JWT authorization request
     * @return String file path
     */
    public String getPrivateKeyFilePath() {
        return privateKeyFilePath;
    }

    /**
     * The file path for the X.509 public certificate submitted to Epic AppMarket
     * @return String file path
     */
    public String getPublicCertificateFilePath() {
        return publicCertificateFilePath;
    }

    /**
     * Get the HAPI FHIR context object associated with this Epic API instance
     * @return HAPI FHIR context object
     */
    public FhirContext getFhirContext() {
        return fhirCtx;
    }

    /**
     * Grabs the access token if it exists and is not expired
     * @return String access token
     */
    public String getAccessToken() {
        Date now = new Date();
        if (accessTokenExpiration == null) {
            logger.debug("No access token expiration, we likely haven't requested one yet");
            accessToken = null;
        } else if (now.after(accessTokenExpiration)) {
            logger.debug("Access token expired (Now: {}, Expires {})", now.getTime(), accessTokenExpiration.getTime());
            accessToken = null;
            accessTokenExpiration = null;
        }
        return accessToken;
    }
}
