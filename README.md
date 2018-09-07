[![Build Status](https://api.travis-ci.org/symbiote-h2020/AuthenticationAuthorizationManager.svg?branch=staging)](https://api.travis-ci.org/symbiote-h2020/AuthenticationAuthorizationManager)
[![codecov.io](https://codecov.io/github/symbiote-h2020/AuthenticationAuthorizationManager/branch/staging/graph/badge.svg)](https://codecov.io/github/symbiote-h2020/AuthenticationAuthorizationManager)

# AuthenticationAuthorizationManager

AuthenticationAuthorizationManager module is responsible for 
providing tokens and certificates that allow applications to search and access resources and components in a secure way.  

**NOTE:** Due to changes in construction of payloads stored in database, migration of data from AAM v2.0 to v3.0 and then from V3 to v4/v5 is required. Necessary script can be found in *./migration_scripts/* directory.

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
https://<yourCoreInterfaceHostname>:8100/coreInterface/v1/get_component_certificate/platform/SymbIoTe_Core_AAM/component/aam
```
There you should see the connection green and the content is Core AAM instance's certificate in PEM format.
