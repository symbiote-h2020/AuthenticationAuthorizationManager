[![Build Status](https://api.travis-ci.org/symbiote-h2020/AuthenticationAuthorizationManager.svg?branch=staging)](https://api.travis-ci.org/symbiote-h2020/AuthenticationAuthorizationManager)
[![codecov.io](https://codecov.io/github/symbiote-h2020/AuthenticationAuthorizationManager/branch/staging/graph/badge.svg)](https://codecov.io/github/symbiote-h2020/AuthenticationAuthorizationManager)

# AuthenticationAuthorizationManager

AuthenticationAuthorizationManager module is responsible for 
providing tokens and certificates that allow applications to search and access resources and components in a secure way.  

**NOTE:** Due to changes in construction of payloads stored in database, migration of data from AAM v2.0 to v3.0 is required. Example script can be found in *./migration_scripts/2.0_to_3.0.js*

## Context
To read more about the project, please see documentation of:
 * [SymbioteCloud](https://github.com/symbiote-h2020/SymbioteCloud)
 * [SymbioteCore](https://github.com/symbiote-h2020/SymbioteCore)
 * [SymbioteSecurity](https://github.com/symbiote-h2020/SymbioteSecurity)
 
In general, symbIoTe is a mediator, an intermediary connecting applications and IoT platforms. The basic functionality is that of a registry service which lists platforms, their resources and properties, while also providing a way to map between the platforms' different APIs.

