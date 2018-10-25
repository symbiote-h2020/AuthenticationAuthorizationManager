FROM openjdk:8-jre-alpine

WORKDIR /home

ENV componentName "AuthenticationAuthorizationManager"
ENV componentVersion 5.0.7
ENV symbIoTeSecurityVersion 27.5.0

COPY ./docker/configure.sh configure.sh

RUN apk --no-cache add \
	git \
	unzip \
	wget \
	bash \
	&& echo "Downloading $componentName $componentVersion" \
	&& wget "https://jitpack.io/com/github/symbiote-h2020/$componentName/$componentVersion/$componentName-$componentVersion-run.jar" \
	&& wget https://jitpack.io/com/github/symbiote-h2020/SymbIoTeSecurity/$symbIoTeSecurityVersion/SymbIoTeSecurity-$symbIoTeSecurityVersion-helper.jar \
	&& wget https://www.bouncycastle.org/download/bcprov-jdk15on-159.jar \
	&& chmod a+x ./configure.sh

EXPOSE 8080 8443

CMD ./configure.sh $symbIoTeSecurityVersion && java $JAVA_HTTP_PROXY $JAVA_HTTPS_PROXY $JAVA_NON_PROXY_HOSTS -jar $(ls *run.jar)