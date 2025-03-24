FROM appiriodevops/ap-microservice-base:0.0.2

MAINTAINER devops@appirio.com

WORKDIR /data

# New Relic configuration file
COPY newrelic.yml /usr/local/share/newrelic/newrelic.yml

# SumoLogic
COPY sumo.conf /etc/sumo.conf
COPY sumo-sources.json ./sumo-sources.json

COPY tech.core.service.identity.jar ./tech.core.service.identity.jar

COPY config.yml ./config.yml

COPY run-service.sh ./run-service.sh

#RUN yum install wget -y; \
#wget -O dd-java-agent.jar 'https://search.maven.org/classic/remote_content?g=com.datadoghq&a=dd-java-agent&v=LATEST'

CMD ["/bin/bash", "/data/run-service.sh"]

EXPOSE 8080 8081 3306 2181 9092
