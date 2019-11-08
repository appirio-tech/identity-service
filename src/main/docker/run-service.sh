# starts sumo logic collector and dropwizard from a Docker container
/usr/local/share/sumocollector/collector start

if [ "$AP_ENV" = "prod" ]
then
	java -Dnewrelic.environment=$AP_ENV -javaagent:/data/dd-java-agent.jar -Ddd.agent.host=$DD_TRACE_AGENT_HOSTNAME -Ddd.agent.port=8126 -Ddd.service.name=$DD_SERVICE_NAME -javaagent:$NEWRELIC_JAR -Djavax.net.ssl.trustStore=/data/TC.prod.ldap.keystore -DZOOKEEPER_HOSTS_LIST=$ZOOKEEPER_HOSTS_LIST -jar /data/tech.core.service.identity.jar server /data/config.yml
else
	java -javaagent:/data/dd-java-agent.jar -Ddd.agent.host=$DD_TRACE_AGENT_HOSTNAME -Ddd.agent.port=8126 -Ddd.service.name=$DD_SERVICE_NAME -Djavax.net.ssl.trustStore=/data/TC.prod.ldap.keystore -DZOOKEEPER_HOSTS_LIST=$ZOOKEEPER_HOSTS_LIST -jar /data/tech.core.service.identity.jar server /data/config.yml
fi


