#!/bin/sh

SERVICE="identity"

# Project root directory of the micro service.
SOURCE_ROOT=$1
# dev|qa|prod
CONFIG=$2
ENV=`echo "$CONFIG" | tr '[:lower:]' '[:upper:]'`
# version
VER=`date "+%Y%m%d%H%M"`

# AWS_REGION=$(eval "echo \$${ENV}_AWS_REGION")
# AWS_ACCESS_KEY_ID=$(eval "echo \$${ENV}_AWS_ACCESS_KEY_ID")
# AWS_SECRET_ACCESS_KEY=$(eval "echo \$${ENV}_AWS_SECRET_ACCESS_KEY")


# configure_aws_cli() {
# 	aws --version
# 	aws configure set aws_access_key_id $AWS_ACCESS_KEY_ID
# 	aws configure set aws_secret_access_key $AWS_SECRET_ACCESS_KEY
# 	aws configure set default.region $AWS_REGION
# 	aws configure set default.output json
# 	echo "Configured AWS CLI."
# }

# configure_aws_cli
# aws s3 cp "s3://appirio-platform-$CONFIG/services/common/dockercfg" ~/.dockercfg

# Elastic Beanstalk Application name
# dev
APPNAME="Development"
if [ "$CONFIG" = "qa" ]; then
    APPNAME="QA"
fi
if [ "$CONFIG" = "prod" ]; then
    APPNAME="Production"
fi

# Application version name to be deployed in Elastic Beanstalk
APPVER="ap-${SERVICE}-${CONFIG}-${VER}"

# Docker resistory
REGISTRY="appiriodevops"
REPO="ap-${SERVICE}-microservice"
TAG="${REPO}:${CONFIG}.${VER}"
IMAGE="${REGISTRY}/${TAG}"

# The key of the profile for AWS CLI configuration
AWS_PROFILE="tc-${CONFIG}"

# S3 Bucket
AWS_S3_BUCKET="appirio-platform-${CONFIG}"
AWS_S3_KEY="services/docker/${TAG}"
# Elastic Beanstalk Environment name
AWS_EB_ENV="ap-${SERVICE}-${CONFIG}"


WORK_DIR=$SOURCE_ROOT/build
DOCKER_DIR=$WORK_DIR/docker
if [ ! -d $DOCKER_DIR ]; then
    mkdir -p $DOCKER_DIR
fi

handle_error() {
  RET=$?
  if [ $RET -ne 0 ]; then
    echo "ERROR: $1"
    exit $RET
  fi
}

echo "***** start deploying the ${SERVICE} service to the ${CONFIG} environment *****"

cd $WORK_DIR

echo "copying Docker-related files"
cp $SOURCE_ROOT/src/main/docker/* $DOCKER_DIR/

echo "copying application jar"
cp $SOURCE_ROOT/target/tech.core.service.identity.jar $DOCKER_DIR/tech.core.service.identity.jar

echo "copying configuration file"
cp $SOURCE_ROOT/target/classes/config.yml $DOCKER_DIR/config.yml

# checking domain
# prod -> topcoder.com, qa -> topcoder-qa.com, dev -> topcoder-dev.com
APPDOMAIN=`cat $DOCKER_DIR/config.yml | grep "authDomain" | sed -e 's/authDomain: //g'`
echo "[CHECK THIS IS CORRECT] application domain: ${APPDOMAIN}"

echo "copying LDAP keystore file"
#cp /mnt/ebs/deploy/topcoder/ap-identity/conf/$CONFIG/TC.prod.ldap.keystore $DOCKER_DIR/TC.prod.ldap.keystore
#aws s3 cp s3://appirio-platform-$CONFIG/application/tc-api-core/$CONFIG/TC.prod.ldap.new.keystore $DOCKER_DIR/TC.prod.ldap.keystore

if [ "$CONFIG" = "qa" ]; then
	aws s3 cp s3://tc-buildproperties-$CONFIG/tc-api-core/TC.prod.ldap.new.keystore $DOCKER_DIR/TC.prod.ldap.keystore
else
    aws s3 cp s3://appirio-platform-$CONFIG/application/tc-api-core/$CONFIG/TC.prod.ldap.sept2024.keystore $DOCKER_DIR/TC.prod.ldap.keystore
fi

echo "copying environment-specific resources"
cat $WORK_DIR/config/sumo-template.conf | sed -e "s/@APINAME@/${SERVICE}/g" | sed -e "s/@CONFIG@/${CONFIG}/g" > $DOCKER_DIR/sumo.conf
cat $WORK_DIR/config/sumo-sources-template.json | sed -e "s/@APINAME@/${SERVICE}/g" | sed -e "s/@CONFIG@/${CONFIG}/g" > $DOCKER_DIR/sumo-sources.json
cat $WORK_DIR/config/newrelic-template.yml | sed -e "s/@APINAME@/${SERVICE}/g" | sed -e "s/@CONFIG@/${CONFIG}/g" > $DOCKER_DIR/newrelic.yml

echo "Logging into docker"
echo "############################"
DOCKER_USER=$(aws ssm get-parameter --name /$CONFIG/build/dockeruser --with-decryption --output text --query Parameter.Value)
DOCKER_PASSWD=$(aws ssm get-parameter --name /$CONFIG/build/dockercfg --with-decryption --output text --query Parameter.Value)
echo $DOCKER_PASSWD | docker login -u $DOCKER_USER --password-stdin

echo "building docker image: ${IMAGE}"
docker build -t $TAG $DOCKER_DIR
handle_error "docker build failed."
docker tag $TAG $IMAGE

VER1=$VER
echo export VER="$VER1" >> "$BASH_ENV"
