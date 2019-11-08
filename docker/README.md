## How to setup development environment for Identity service in local machine

### Prerequisite Tools

- Java Development Kit 8 (http://www.oracle.com/technetwork/java/javase/downloads/jdk8-downloads-2133151.html)
- Apache Maven (https://maven.apache.org/download.cgi)
- git (https://git-scm.com/downloads)
- Docker (https://www.docker.com/community-edition#/download)


### Informix

The docker image for Informix is based on ibmcom/informix-developer-database (https://hub.docker.com/r/ibmcom/informix-developer-database/).
At the first time, run Docker container with this image as follows:

    docker run -it --name tc-informix --privileged -p 9088:9088 -p 9089:9089 -p 27017:27017 -p 27018:27018 -p 27883:27883 -e LICENSE=accept appiriodevops/tc-identity-informix:0.1.0

This performs a disk initialization. After exiting from the shell, the container is stopped.

Start the Informix containder with `docker start` command.

    docker start tc-informix

And attach to the container with shell.

    docker exec -it tc-informix bash

Inside the container, run the setup script to create some tables and records for Identity service. (Run the script in the /setup directory.)

    cd /setup
    sh ./setup.sh

And set password for the informix user in the container.

    sudo su - 
    passwd informix
    Enter new UNIX password: informix
    Retype new UNIX password: informix
    exit
    exit

Now the informix database is ready to connect with the following information.
- hostname: IP address assigned to your Docker service. If your container is running on docker-machine, you can check the IP address with `docker-machine ip [MACHINE-NAME]`, otherwise just try localhost or 127.0.0.1.

      docker-machine ip default

- database: dev
- username/password: informix/informix

If you want to conenct to the database with JDBC, the connection spec is following:

    url: jdbc:informix-sqli://[DOCKER-IP]:9088/common_oltp:informixserver=dev
    user: informix
    password: informix


### Other services (MySQL,OpenLDAP,Kafka,Redis)

Identity service needs several services to work. They can be run in the docker with docker-compose. 
Before doing docker-compose, set the environment variable "DOCKER_IP" which is supposed to have valid IP address or hostname assigned to your Docker service. 
	
	export DOCKER_IP=[YOUR DOCKER'S IP ADRESS]
	
	For Local setup
	export DOCKER_IP=127.0.0.1
	
And then, do the docker-compose as follows:

    docker-compose up -d

Please look at docker-compose.yml for details.

If you want to conenct to the MySQL with JDBC, the connection spec is following:

    url: jdbc:mysql://[DOCKER_IP]:3306/Authorization
    user: coder
    password: topcoder

### Identity Service

Replace some configuration files with templates for local development.
 
    cp token.properties.localdev token.properties
    cp src/main/resources/config.yml.localdev src/main/resources/config.yml

Build Identity service with Maven. Note if you can not download jars from maven.appirio.net:8080, you can copy the jars from *./lib* folder to your local maven repo (${user.home}/.m2/repository)
    mvn package

Set the following environment variables before running Identity service.

    export DOCKER_IP=[YOUR DOCKER'S IP ADRESS]
    export ZOOKEEPER_HOSTS_LIST=[YOUR DOCKER'S IP ADRESS]:2181

Run Identity service with the following comamnd-line.

    java -jar target/tech.core.service.identity.jar server target/classes/config.yml

Configure your IDE with the following information if you want to run/debug on it.

- Main class: com.appirio.tech.core.service.identity.IdentityApplication
- Arguments: server target/classes/config.yml
- Environment variables:
    - DOCKER_IP=[YOUR DOCKER'S IP ADRESS]
    - ZOOKEEPER_HOSTS_LIST=[YOUR DOCKER'S IP ADRESS]:2181

Confirm the following commands respond result with 200 status.

- GET example

      GET http://localhost:8080/v3/users/validateHandle?handle=test

- POST example

      POST http://localhost:8080/v3/users
      Content-Type: application/json
      Body:
      {
          "param": {
              "handle": "johndoe",
              "firstName": "John",
              "lastName": "Doe",
              "email": "jdoe@test.topcoder.com",
              "active": true,
              "country": {
                  "isoAlpha3Code": "USA"
              },
              "credential": {
                  "password": "topcoder123"
              }
          }
      }

