#!/bin/sh

SERVICE="identity"

# Project root directory of the micro service.
SOURCE_ROOT=$1
# dev|qa|prod
CONFIG=$2
# version
VER=`date "+%Y%m%d%H%M"`


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

function handle_error() {
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
cp /mnt/ebs/deploy/topcoder/ap-identity/conf/$CONFIG/TC.prod.ldap.keystore $DOCKER_DIR/TC.prod.ldap.keystore

echo "copying environment-specific resources"
cat $WORK_DIR/config/sumo-template.conf | sed -e "s/@APINAME@/${SERVICE}/g" | sed -e "s/@CONFIG@/${CONFIG}/g" > $DOCKER_DIR/sumo.conf
cat $WORK_DIR/config/sumo-sources-template.json | sed -e "s/@APINAME@/${SERVICE}/g" | sed -e "s/@CONFIG@/${CONFIG}/g" > $DOCKER_DIR/sumo-sources.json
cat $WORK_DIR/config/newrelic-template.yml | sed -e "s/@APINAME@/${SERVICE}/g" | sed -e "s/@CONFIG@/${CONFIG}/g" > $DOCKER_DIR/newrelic.yml

echo "building docker image: ${IMAGE}"
sudo docker build -t $IMAGE $DOCKER_DIR
handle_error "docker build failed."

echo "pushing docker image: ${IMAGE}"
sudo docker push $IMAGE
handle_error "docker push failed."

echo "creating Dockerrun.aws.json from template."
DOCKERRUN="${WORK_DIR}/eb/Dockerrun.aws.json"
DR_TMP="${DOCKERRUN}.template"
cat $DR_TMP | sed -e "s/@IMAGE@/${TAG}/g" > $DOCKERRUN
cat $DOCKERRUN

cd ${WORK_DIR}/eb
echo "creating ${TAG}.zip"
jar cMf ${TAG}.zip Dockerrun.aws.json .ebextensions

echo "pushing ${TAG}.zip to S3: ${AWS_S3_BUCKET}/${AWS_S3_KEY}"
aws s3api put-object --profile $AWS_PROFILE --bucket "${AWS_S3_BUCKET}" --key "${AWS_S3_KEY}" --body ${WORK_DIR}/eb/${TAG}.zip
handle_error "aws s3api put-object failed."

echo "creating new application version $APPVER in ${APPNAME} from s3:${AWS_S3_BUCKET}/${AWS_S3_KEY}"
aws elasticbeanstalk create-application-version --profile $AWS_PROFILE --application-name $APPNAME --version-label $APPVER --source-bundle S3Bucket="$AWS_S3_BUCKET",S3Key="$AWS_S3_KEY"
handle_error "aws elasticbeanstalk create-application-version failed."

echo "updating elastic beanstalk environment ${AWS_EB_ENV} with the version ${APPVER}."
# assumes beanstalk app for this service has already been created and configured
aws elasticbeanstalk --profile $AWS_PROFILE update-environment --environment-name $AWS_EB_ENV --version-label $APPVER
handle_error "aws elasticbeanstalk pdate-environment failed."
