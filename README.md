# Epic FHIR [Backend Service](https://fhir.epic.com/Documentation?docId=oauth2&section=BackendOAuth2Guide) Authentication Wrapper for [HAPI FHIR](https://hapifhir.io/) client (For Java 8)

*Note: HAPI FHIR dropped support for Java 8 in v6.0.0. This version uses HAPI FHIR v5.7.9 that contains some vunerable dependencies. If you're using Java 11+, it is recommended to use the [Java 11+ version](https://github.com/ukpathologyinformatics/Epic-FHIR-API-Java11).*

A Java 8 wrapper implementation to enable Epic FHIR
[Backend Service](https://fhir.epic.com/Documentation?docId=oauth2&section=BackendOAuth2Guide) authentication
with the [HAPI FHIR](https://hapifhir.io/) Java FHIR implementation with minimal setup.

### Installing and Using Locally
##### Requires
* Java 8+
* Maven 3.6+
##### Installing to Local Maven Repository
To install locally, simply clone this repository and issue the following command:
```bash
mvn clean install
```
##### Using in Maven Projects
Once the Maven project has compiled and been installed to your local repository, you can add it as a dependency to other projects using:
```xml
<dependencies>
    ...
    <dependency>
        <groupId>edu.uky.pml.epic</groupId>
        <artifactId>fhir-api</artifactId>
        <version>0.1-8</version>
    </dependency>
    ...
</dependencies>
```
### Creating a Epic API Wrapper Instance
Using the Epic API wrapper requires some registration and setup with either the [Epic FHIR](https://fhir.epic.com/Developer/Apps) ([guide](https://fhir.epic.com/Documentation?docId=oauth2&section=BackendOAuth2Guide)) or [Epic AppMarket](https://appmarket.epic.com/Developer/Apps) ([guide](https://appmarket.epic.com/Article?docId=oauth2&section=BackendOAuth2Guide)) Developer Apps section. The respective guide for which section your account has access to details how to register your app and build your private key and public certificate for signing and submission. Once your app is submitted, you will receive a `Client ID` you can use with your private key `.pem` and FHIR endpoint to build your EpicAPI wrapper instance.

##### Simple Example
```java
// Using the Epic FHIR Sandbox as an example
String epicURL = "https://fhir.epic.com/interconnect-fhir-oauth";

// This should be the 'Client ID' associated with your Epic FHIR or AppMarket app
String clientId = "client_id";

// This should be the private key used to sign JWT requests and generate the
// publickey509.pem you submitted to Epic FHIR or AppMarket
String privateKeyFile = "path/to/privatekey.pem";

// Instantiate a simple EpicAPI wrapper instance
EpicAPI epicAPI = new EpicAPI(epicURL, clientId, privateKeyFile);
```

##### Instance with authorization request JWT validation:
```java
// Using the Epic FHIR Sandbox as an example
String epicURL = "https://fhir.epic.com/interconnect-fhir-oauth";

// This should be the 'Client ID' associated with your Epic FHIR or AppMarket app
String clientId = "client_id";

// This should be the private key used to sign JWT requests and generate the
// publickey509.pem you submitted to Epic FHIR or AppMarket
String privateKeyFile = "path/to/privatekey.pem";

// This should be the public certificate file you uploaded to Epic FHIR or AppMarket
String publicCertFile = "path/to/publicCert509.pem";

// Instantiate a simple EpicAPI wrapper instance
EpicAPI epicAPI = new EpicAPI(epicURL, clientId, privateKeyFile, publicCertFile);
```

### Using your EpicAPI wrapper instance

The actual use of the wrapper is beyond the scope of this project. For more information please refer to the [HAPI FHIR documentation](https://hapifhir.io/hapi-fhir/docs/). Provided here is a simple example that works with the Epic FHIR sandbox data.

*Note that the EpicAPI keeps your HAPI FHIR context as an accessible instance member to prevent recreating contexts, which HAPI FHIR advises against as it is memory inefficient to do so.*

```java
// Instantiate a generic restful client
IGenericClient client = epicAPI.getFhirClient();

// Search for a patient by MRN
Bundle bundle = client
    .search()
    .forResource(Patient.class)
    .where(
        Patient.IDENTIFIER.exactly().systemAndValues("MRN", "some_mrn")
    )
    .returnBundle(Bundle.class).execute();

// Process the search results
List<IBaseResource> patients = new ArrayList<>(
    BundleUtil.toListOfResources(
        epicAPI.getFhirContext(), bundle
    )
);

// Grab the first (patient) result and build a human-readable JSON string
String string = epicAPI
        .getFhirContext()
        .newJsonParser()
        .setPrettyPrint(true)
        .encodeResourceToString(patients.get(0));

// Print the patient information to the screen
System.out.println(string);
```