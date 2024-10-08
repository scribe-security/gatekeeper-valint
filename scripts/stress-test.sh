#!/bin/bash


# This script is used to stress test the application by sending a large number of requests to the server.
# This script will generate a set of deployment and deploy to k8s and time the admission response.
# First Use case is deploying a single deployment with 10 images.

TMP_DIR=".tmp"
STRESS_PATH="stress_deployment.yaml"
STRESS_DEPLOYMENT_PATH="$TMP_DIR/$STRESS_PATH"

parse_args() {
  while getopts "n:c:DxCx" arg; do
    case "$arg" in
      n)
        echo "Test name: $OPTARG"
        TEST_NAME=$OPTARG
        ;;
      c)
        echo "Image count: $OPTARG"
        IMAGE_COUNT=$OPTARG
        ;;
      D)
        echo "Deploying to k8s"
        DEPLOY=true
        ;;
      C)
        echo "Cleaning k8s"
        CLEAN=true
        ;;
      *)
        echo "Invalid option: -$OPTARG" >&2
        exit 1
        ;;
    esac
  done
  shift $((OPTIND - 1))
}

## Create depoyment and then push to tmp.file
create_deployment() {
  DEP_PATH=$1
  COUNT=$2
  cat <<EOF >> $DEP_PATH
apiVersion: apps/v1
kind: Deployment
metadata:
  name: stress-deployment
  labels:
    app: stress-deployment
spec:
  replicas: 0 # testing purposes only
  selector:
    matchLabels:
      app: stress-deployment
  template:
    metadata:
      labels:
        app: stress-deployment
    spec:
      containers:
EOF

  for i in $(seq 1 $COUNT); do
    cat <<EOF >> $DEP_PATH
      - name: nginx-$i
        image: nginx:latest
EOF
    done
}

deploy() {
  DEP_PATH=$1
  COUNT=$2
  echo "<<<<<<<<<<< Timing Deployment >>>>>>>>>>>>>"
  TEST_LOG=$(time kubectl apply -f $DEP_PATH)
  if [ ! -z "$TEST_NAME" ]; then
    echo $DEP_PATH > "$TMP_DIR/$TEST_NAME-$COUNT.log"
    echo "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<" >> "$TMP_DIR/$TEST_NAME-$COUNT.log"
    echo $TEST_LOG >> "$TMP_DIR/$TEST_NAME-$COUNT.log"
  fi
  echo $TEST_LOG
  
  echo "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
}

clean() {
  DEP_PATH=$1
  kubectl delete -f $DEP_PATH
}

parse_args "$@"

if [ ! -z "$DEPLOY" ]; then
    create_deployment $STRESS_DEPLOYMENT_PATH $IMAGE_COUNT 
    clean $STRESS_DEPLOYMENT_PATH
    deploy $STRESS_DEPLOYMENT_PATH $IMAGE_COUNT
fi

if [ ! -z "$CLEAN" ]; then
    clean $STRESS_DEPLOYMENT_PATH
fi