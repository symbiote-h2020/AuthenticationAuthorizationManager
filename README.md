[![Build Status](https://api.travis-ci.org/symbiote-h2020/AuthenticationAuthorizationManager.svg?branch=staging)](https://api.travis-ci.org/symbiote-h2020/AuthenticationAuthorizationManager)
[![codecov.io](https://codecov.io/github/symbiote-h2020/AuthenticationAuthorizationManager/branch/staging/graph/badge.svg)](https://codecov.io/github/symbiote-h2020/AuthenticationAuthorizationManager)

# AuthenticationAuthorizationManager

AuthenticationAuthorizationManager module is responsible for 
providing tokens and certificates that allow applications to search and access resources and components in a secure way.  

**NOTE:** Due to changes in construction of payloads stored in database, migration of data from AAM v2.0 to v3.0 and then from V3 to v4/v5 is required. Necessary script can be found in *./migration_scripts/* directory both for Core AAM and Platform AAM.
Depending on your release, you might need to run both scripts. More specifically:
* if you have ***1.x*** release of symbIoTe (i.e. 2.x release of AAM) you need to run both ***2.0_to_3.0.js*** and ***3.0_to_4.0.js***
* if you have ***2.x*** release of symbIoTe (i.e. 3.x release of AAM) you need to run only ***3.0_to_4.0.js***
To run the script you can simply execute the following command:   
`mongo {mongo_host}:{mongo_port} {script.js}`   
e.g. 
`mongo localhost:27017 3.0_to_4.0.js`   

**DISCLAIMER:** Regarding the platform migration scripts, all the accounts will be automatically set to ***ACTIVE*** 
with the ***serviceConsent*** set to true. This is not GDPR-compliant, but we recommend this approach for testing 
environments. For production, we recommend to run the ***core scripts*** on the platform side as well, and to require email 
verification and service consent request.

## Context
To read more about the project, please see documentation of:
 * [SymbioteCloud](https://github.com/symbiote-h2020/SymbioteCloud)
 * [SymbioteCore](https://github.com/symbiote-h2020/SymbioteCore)
 * [SymbioteSecurity](https://github.com/symbiote-h2020/SymbioteSecurity)
 
In general, symbIoTe is a mediator, an intermediary connecting applications and IoT platforms. The basic functionality is that of a registry service which lists platforms, their resources and properties, while also providing a way to map between the platforms' different APIs.

## Requirements
For proper activity of the AuthenticationAuthorizationManager, some of the additional services needs to be configured:
* Core AAM (Root)
    * RabbitMQ 3.6+
    * MongoDB 3.6+
    * Cloud Services (CoreConfigService, EurekaService, ZipkinService, Administration)
* Intermediate AAM(Platform) / Enabler
    * Mongo DB
    * Cloud Services (CloudConfigService, EurekaService, ZipkinService)
* Smart Space AAM:
    * Mongo DB 

All of the Cloud Services can be found on official symbIoTe repo: [github](https://github.com/symbiote-h2020)
   
## Core AAM Setup
To properly start Core AAM, following steps need to be made.
### Certificate creation
You need to create a PKCS12 keystore containing a certificate:
* self-signed
* with CA property enabled
* with the following encryption params
    * SIGNATURE_ALGORITHM=SHA256withECDSA
    * CURVE_NAME=secp256r1
    * KEY_PAIR_GEN_ALGORITHM=ECDSA
* with the CN value set according to AAMConstants.java field CORE_AAM_INSTANCE_ID value (e.g. currently SymbIoTe_Core_AAM)
* with the certificate entry name "symbiote_core_aam"

This keystore will be used to self-initiliaze the AAM codes as Core AAM.  
For creating it you can e.g. use the [OpenSSL tool](https://linux.die.net/man/1/openssl)
### SSL certificate
To secure communication between the clients and your platform instance you need an SSL certificate(s) for your Core AAM and for your CoreInterface. Should they be deployed on the same host, the certificate can be reused in both components.

Moreover if they are on the same host and the AAM is not exposed directly, meaning:
* all your components run on the same machine or isolated network
* external clients access through the CoreInterface

you don't need to put an SSL certificate for your AAM.
#### How to issue the certificate
Issue using e.g. [https://letsencrypt.org/](https://letsencrypt.org/)

A certificate can be obtained using the certbot shell tool ([https://certbot.eff.org/](https://certbot.eff.org/)) only for resolvable domain name.

Instructions for the Ubuntu (Debian) machine are the following: 
##### Install certbot:
```bash
$ sudo apt-get install software-properties-common
$ sudo add-apt-repository ppa:certbot/certbot
$ sudo apt-get update
$ sudo apt-get install certbot python-certbot-apache
```
##### Obtain the certificate by executing:
```bash
$ certbot --apache certonly
```
**NOTE:** Apache port (80 by default) should be accessible from outside on your firewall.

Select option Standalone (option 2) and enter your domain name.

##### Upon successful execution navigate to the location: 
```bash
/etc/letsencrypt/live/<domain_name>/ 
```
where you can find your certificate and private key (5 files in total, cert.pem  chain.pem  fullchain.pem  privkey.pem  README).

#### How to create a Java Keystore with the issued SSL certificate, required for Core deployment
Create a Java Keystore containing the certificate. Use the KeyStore Explorer application to create JavaKeystore (http://keystore-explorer.org/downloads.html):
1. (optionally) Inspect obtained files using Examine --> Examine File
2. Create a new Keystore --> PKCS #12
3. Tools --> Import Key Pair --> PKCS #8
4. Deselect Encrypted Private Key
    * Browse and set your private key (privkey.pem)
    * Browse and set your certificate (fullchain.pem)
5. Import --> enter alias for the certificate for this keystore
6. Enter password
7. File --> Save --> enter previously set password  --> <filename>.p12

**Note:** Filename will be used as configuration parameter of the Core AAM component
```
server.ssl.key-store=classpath:<filename>.p12
```
If you do not want to use KeyStore Explorer find some helpful resources below:
* https://community.letsencrypt.org/t/how-to-get-certificates-into-java-keystore/25961/19
* http://stackoverflow.com/questions/34110426/does-java-support-lets-encrypt-certificates
### Building the Core AAM
Build it using:
```bash 
$ gradle assemble --refresh-dependencies
```

### Configuring the Core AAM properties
Once one has done previous actions, you need to create a boostrap.properties. Templates with the instructions can be found in 
* *src/main/resources/templates/core.properties* - if using spring cloud
* *src/main/resources/templates/core_standalone.properties* - if not using spring cloud

You need to put this file next to the assembled AAM *-run.jar file. 
Directory:
* the generated in step 1 keystore Core AAM symbiote certificate and keys
* the generated in step 2 keystore generated for your SSL certificate (if the AAM is to be for any reason exposed)

### Running and veryfing that Core AAM is working
```bash 
$ java -jar AuthenticationAuthorizationManager-<version_that_was_built>-run.jar
```
Verify all is ok by going to:
```
http(s)://<yourCAAMHostname>:<selected port>/get_available_aams
```
There you should see the connection green and the content are the available symbiote security endpoints (currently only your Core AAM as no platforms are registered in it yet)

Also you can check that the certificate listed there matches the one you get here:
```
http(s)://<yourCAAMHostname>:<selected port>/get_component_certificate/platform/SymbIoTe_Core_AAM/component/aam
```
#### Checking the coreInterface
Verify all is ok by going to:
```
https://<yourCoreInterfaceHostname>/coreInterface/aam/get_component_certificate/platform/SymbIoTe_Core_AAM/component/aam
```
There you should see the connection green and the content is Core AAM instance's certificate in PEM format.
## User management

To manage users in the system, AAM exposes AMQP and REST interfaces, depending on the profile of the AAM.
* **Core AAM**: AMQP and REST api
* **Platform AAM**: AMQP and REST api
* **Smart Space AAM**: REST api

Users can have two roles in the system ([UserRole](https://github.com/symbiote-h2020/SymbIoTeSecurity/blob/develop/src/main/java/eu/h2020/symbiote/security/commons/enums/UserRole.java)): 
* USER - default symbIoTe's data consumer role
* SERVICE_OWNER - symbIoTe-enabled service's (platform's and smart space's) owner account type, used to release administration attributes

**NOTE: Service Owners can't be registered in Platform AAMs!**

What's more, user's account in the system contains [AccountStatus](https://github.com/symbiote-h2020/SymbIoTeSecurity/blob/develop/src/main/java/eu/h2020/symbiote/security/commons/enums/AccountStatus.java). 
### Payload
To manage users in the system, proper [UserManagementRequest](https://github.com/symbiote-h2020/SymbIoTeSecurity/blob/develop/src/main/java/eu/h2020/symbiote/security/communication/payloads/UserManagementRequest.java)
should be send, filled depending on operation type:

* CREATE:
    * admin credentials - for operation authorization
    * user details - information about username, password, recovery mail etc.
    
    NOTE: Creating user, we have to be sure that he agrees to service terms - **it is required for user creation!**
* UPDATE:
    * admin credentials - for operation authorization
    * user credentials - for operation authorization
    * user details - information about new password, new mail or analytics and research consent update(**MUST contain valid username!**)

* DELETE:
    * admin credentials - for operation authorization
    * user credentials (only username) - information about username
* FORCED_UPDATE:
    * admin credentials - for operation authorization
    * user credentials (only username) - information about username to resolve user
    * user details - information about new password, new mail, analytics and research consent update, service terms agreement and account status (**MUST contain valid username!**)

* ATTRIBUTES_UPDATE:
    * admin credentials - for operation authorization
    * user credentials (only username) - information about username
    * attributes map - information about attributes to be included into token

#### Example
Example of the valid CREATE request, for user named *testApplicationUsername*:
```json
{
	"administratorCredentials": {
		"username": "AAMOwner",
		"password": "AAMPassword"
	},
	"userCredentials": {
		"username": "", 
		"password": ""
	},
	"userDetails": {
		"recoveryMail": "null@dev.null",
		"role": "USER",
		"status": "NEW",
		"attributes": {},
		"clients": {},
		"serviceConsent": true,
		"analyticsAndResearchConsent": false,
		"credentials": {
			"username": "testApplicationUsername",
			"password": "testApplicationPassword"
		}
	},
	"operationType": "CREATE"
}
```
Example of the valid UPDATE request:
```json
{
	"administratorCredentials": {
		"username": "AAMOwner",
		"password": "AAMPassword"
	},
	"userCredentials": {
		"username": "testApplicationUsername",
		"password": "testApplicationPassword"
	},
	"userDetails": {
		"recoveryMail": "newRecoveryMail",
		"role": "USER",
		"status": "NEW",
		"attributes": {},
		"clients": {},
		"serviceConsent": true,
		"analyticsAndResearchConsent": false,
		"credentials": {
			"username": "testApplicationUsername",
			"password": ""
		}
	},
	"operationType": "UPDATE"
}
```
Example of the valid DELETE request:
```json
{
	"administratorCredentials": {
		"username": "AAMOwner",
		"password": "AAMPassword"
	},
	"userCredentials": {
		"username": "",
		"password": ""
	},
	"userDetails": {
		"recoveryMail": "",
		"role": "USER",
		"status": "NEW",
		"attributes": {},
		"clients": {},
		"serviceConsent": true,
		"analyticsAndResearchConsent": false,
		"credentials": {
			"username": "testApplicationUsername",
			"password": ""
		}
	},
	"operationType": "DELETE"
}
```
Example of the valid FORCE_UPDATE request:
```json
{
	"administratorCredentials": {
		"username": "AAMOwner",
		"password": "AAMPassword"
	},
	"userCredentials": {
		"username": "",
		"password": ""
	},
	"userDetails": {
		"recoveryMail": "newMail@mail.mail",
		"role": "USER",
		"status": "NEW",
		"attributes": {},
		"clients": {},
		"serviceConsent": true,
		"analyticsAndResearchConsent": true,
		"credentials": {
			"username": "testApplicationUsername",
			"password": "NewPassword"
		}
	},
	"operationType": "FORCE_UPDATE"
}
```
Example of the valid ATTRIBUTES_UPDATE request:
```json
{
	"administratorCredentials": {
		"username": "AAMOwner",
		"password": "AAMPassword"
	},
	"userCredentials": {
		"username": "",
		"password": ""
	},
	"userDetails": {
		"recoveryMail": "",
		"role": "USER",
		"status": "NEW",
		"attributes": {
			"attributeExample": "attributeValueExample"
		},
		"clients": {},
		"serviceConsent": true,
		"analyticsAndResearchConsent": false,
		"credentials": {
			"username": "testApplicationUsername",
			"password": ""
		}
	},
	"operationType": "ATTRIBUTES_UPDATE"
}
```

### REST
To manage users using REST api, send HTTP POST request on:

```java 
https://<localAAMAddress>/manage_users
```

containing properly filled [UserManagementRequest](https://github.com/symbiote-h2020/SymbIoTeSecurity/blob/develop/src/main/java/eu/h2020/symbiote/security/communication/payloads/UserManagementRequest.java) (see previous section).
As a response, HttpStatus is returned with [ManagementStatus](https://github.com/symbiote-h2020/SymbIoTeSecurity/blob/develop/src/main/java/eu/h2020/symbiote/security/commons/enums/ManagementStatus.java) in message body.

### AMQP
To manage users using AMQP api, send properly filled [UserManagementRequest](https://github.com/symbiote-h2020/SymbIoTeSecurity/blob/develop/src/main/java/eu/h2020/symbiote/security/communication/payloads/UserManagementRequest.java) (see previous section) on the rabbit.queue.manage.user.request queue:
```java
 // issue app registration over AMQP
 byte[] response = rabbitTemplate.sendAndReceive(userManagementRequestQueue,
     new Message(mapper.writeValueAsString(userManagementRequest).getBytes(), new MessageProperties())).getBody();

ManagementStatus appRegistrationResponse = mapper.readValue(response,
     ManagementStatus.class);
```
As a response, [ManagementStatus](https://github.com/symbiote-h2020/SymbIoTeSecurity/blob/develop/src/main/java/eu/h2020/symbiote/security/commons/enums/ManagementStatus.java) is returned as a byte array.
