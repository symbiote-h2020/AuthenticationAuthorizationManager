#!/bin/bash

symbIoTeSecurityVersion=$1
echo "Configure and start aam with symbIoTeSecurityVersion $symbIoTeSecurityVersion"
ls *.p12
isConfigured=$?
if [ $isConfigured -gt 0 ]; then
  echo "The deployment is not configured"
  # AAM security - keystore generation
  java $JAVA_HTTP_PROXY $JAVA_HTTPS_PROXY $JAVA_SOCKS_PROXY $JAVA_NON_PROXY_HOSTS -cp SymbIoTeSecurity-$symbIoTeSecurityVersion-helper.jar:bcprov-jdk15on-159.jar eu.h2020.symbiote.security.helpers.ServiceAAMCertificateKeyStoreFactory cert.properties
fi
