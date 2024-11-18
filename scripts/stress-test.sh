#!/bin/bash


# This script is used to stress test the application by sending a large number of requests to the server.
# This script will generate a set of deployment and deploy to k8s and time the admission response.
# First Use case is deploying a single deployment with 10 images.

TMP_DIR=".tmp"
STRESS_PATH="stress_deployment.yaml"
STRESS_DEPLOYMENT_PATH="$TMP_DIR/$STRESS_PATH"
VALINT_BINARY=../valint/snapshot/main_linux_amd64_v1/valint
IMAGE_COUNT=1
list_nginx_images=( "alpine:3.18.9" "alpine:3.18.8" "alpine:3.18.7" "alpine:3.18.6" "alpine:3.18.5" "alpine:3.18.4" "alpine:3.18.4" "alpine:3.18.3" "alpine:3.18.2" "alpine:3.20.3" "alpine:3.20.2" "alpine:3.20.1" "alpine:3.19.4" "alpine:3.19.3" "alpine:3.19.2" "alpine:3.19.1" "nginx:1.21.6" "nginx:1.21.5" "nginx:1.21.3" "nginx:1.21.1" "nginx:1.26" "nginx:1.25" "nginx:1.24" "nginx:1.23" "nginx:1.22" "nginx:1.21" "nginx:1.20" "nginx:1.19" "nginx:1.18" "nginx:1.17" "nginx:1.16" "nginx:1.15" "nginx:1.14" "nginx:1.13" "nginx:1.12" "nginx:1.11" "nginx:1.10" "nginx:1.9" "nginx:1.8" "nginx:1.7")
parse_args() {
  while getopts "n:c:p:DxCxSxMx" arg; do
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
      M)
        echo "Multi tag images"
        MULTI_TAG=true
        ;;
      p)
        echo "Multi Pods count: $OPTARG"
        POD_COUNT=$OPTARG
        ;;
      S)
       echo "Sign images"
       SIGN=true
       ;;  
      *)
        echo "Invalid option: -$OPTARG" >&2
        exit 1
        ;;
    esac
  done
  shift $((OPTIND - 1))
}

sign_images() {
  COUNT=$1
  for i in $(seq 0 $COUNT); do
    echo "Signing image: $i"
    if [ ! -z "$MULTI_TAG" ]; then
      docker pull ${list_nginx_images[$i]}
      $VALINT_BINARY bom ${list_nginx_images[$i]} -o attest
    fi
  done

  if [ -z "$MULTI_TAG" ]; then
    docker pull nginx:latest
    $VALINT_BINARY bom nginx:latest -o attest
  fi

}

## Create depoyment and then push to tmp.file
create_deployment() {
  DEP_PATH=$1
  COUNT=$2
  SUFFIX=$3
  cat <<EOF >> $DEP_PATH
apiVersion: apps/v1
kind: Deployment
metadata:
  name: stress-deployment-$SUFFIX
  labels:
    app: stress-deployment-$SUFFIX
spec:
  replicas: 0 # testing purposes only
  selector:
    matchLabels:
      app: stress-deployment-$SUFFIX
  template:
    metadata:
      labels:
        app: stress-deployment-$SUFFIX
    spec:
      containers:
EOF

  for i in $(seq 0 $COUNT); do

    if [ ! -z "$MULTI_TAG" ]; then
      IMAGE=${list_nginx_images[$i]}
    else
      IMAGE="nginx:latest"
    fi

    cat <<EOF >> $DEP_PATH
      - name: nginx-$i
        image: $IMAGE
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

set -x
clean() {
  DEP_PATH=$1
  SUFFIX=$2
  kubectl delete -f $DEP_PATH 2>/dev/null || true
}

parse_args "$@"

if [ ! -z "$DEPLOY" ]; then
    if [ ! -z "$POD_COUNT" ]; then
      echo "Deploying $POD_COUNT pod"
      # Range is 0 to POD_COUNT - 1
      for i in $(seq 0 $((POD_COUNT - 1))); do
        DEPLOYMENT_NAME=""$TMP_DIR/$i-$STRESS_PATH""
        # Run IN background
        create_deployment "$DEPLOYMENT_NAME" "$IMAGE_COUNT" "$i"
        clean "$DEPLOYMENT_NAME"
        deploy "$DEPLOYMENT_NAME" "$IMAGE_COUNT" &
      done

      # Wait for all background jobs to finish
      wait
    else
        create_deployment "$STRESS_DEPLOYMENT_PATH" "$IMAGE_COUNT" "single"
        clean "$STRESS_DEPLOYMENT_PATH"
        deploy "$STRESS_DEPLOYMENT_PATH" "$IMAGE_COUNT"
    fi

fi

if [ ! -z "$CLEAN" ]; then
    clean $STRESS_DEPLOYMENT_PATH
fi

if [ ! -z "$SIGN" ]; then
    sign_images $IMAGE_COUNT 
fi