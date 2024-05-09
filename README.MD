# Simple XMS based .net application on Linux docker container
Intention of this simple example is to have the base environment on linux container ready for troubleshooting connection to IBM MQ using TLS when running on linux docker container.
The code is only intended for quick **testing and troubleshooting** and illustrating the base concept.

## Making environment variables avaialble for docker container
Add .env file in root folder, same location as docker-compose.yaml file, containing environment variables which are specified in the docker-compose.yml and docker-compose.override.yml file.

## Enabling/Disabling TLS (connecting without certificate requirement)
For disabling TLS upon connection to queuemanger, set MQ_TLS_DISABLED=true in .env file.
For enabling TLS set MQ_TLS_DISABLED=false and make sure other TLS/certificate properties are provided

### Providing certificates
-  Make sure client certificate is added to the "cert" folder at project root (cert folder, at same level as docker-compse files). Client certificate need to be a .pfx or .p12 file.
-  Make sure server intermediate and root certificates are added to the cert folder as well for certificate chain validation. Server certificates are added to linux image at the start of dockerfile as part of the base image. Make sure that what is stated in docker file is matching server certs that has been added in cert folder and as environemnt variable in .env file.

## IBM XMS Trace
-  If enabled (env variables mapped in docker-compose.override.yml) detailed IBM MQ trace log will be created for client side in a folder names "mqtraces" at the root of the project folder (same level as docker-comopse files)

## Running application
-  Make sure Docker Desktop is installed on your local machine and linux containers are activated
-  Using Visual studio make sure docker-compose is set as start up project (if not already set as default then right click on docker-compose project file in visual studio solution explorer and select "Set as start up project"). Now start with docker-compose from the menu.
-  You can also run from commandline by going to root folder and and run "docker-compose up --build". Make sure .env file contains expected environment variables.

## Environment variables (example values)
-  CERT_ROOTCA_SRC=vcc-root-ca-g2.pem
-  CERT_ROOTCA_DEST=vcc-root-ca-g2.crt
-  CERT_SUBCA_SRC=vcc-subca-06-g3.pem
-  CERT_SUBCA_DEST=vcc-subca-06-g3.crt
-  MQ_HOST=vcc141t.mq.volvocars.net
-  MQ_PORT=1414
-  MQ_QMGR=VCC141T
-  MQ_QUEUE_NAME=VCC7842.TESTDATA
-  MQ_CHANNEL=CLIENTS.OEMAN
-  MQ_CONNECTION_MODE=1
-  MQ_TLS_DISABLED=false
-  MQ_CLIENT_CERTIFICATE_PATH=/app/cert/your-client-certificate.pfx
-  MQ_CLIENT_CERTIFICATE_PASSWORD=add-your-client-certificate-password-here
-  MQ_CLIENT_CERTIFICATE_LABEL=add-client-certificate-label-here
-  MQ_SSL_CIPHER_SPEC=TLS_RSA_WITH_AES_256_CBC_SHA256
-  MQ_SSL_CERT_REPOSITORY=*USER
-  MQ_SSL_PEER_NAME=
-  XMS_TRACE_FORMAT=ADVANCED
-  XMS_TRACE_ON=1
