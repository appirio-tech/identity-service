# starts sumo logic collector and dropwizard from a Docker container
/usr/local/share/sumocollector/collector start

if [ "$AP_ENV" = "prod" ]
then
	java  -DZOOKEEPER_HOSTS_LIST=$ZOOKEEPER_HOSTS_LIST -jar /data/tech.core.service.identity.jar server /data/config.yml
else
	java  -DZOOKEEPER_HOSTS_LIST=$ZOOKEEPER_HOSTS_LIST -jar /data/tech.core.service.identity.jar server /data/config.yml
fi


