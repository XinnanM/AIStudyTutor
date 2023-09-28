#!/bin/bash
set -x
awslocal s3 mb s3://ai-study-tutor-local
KINESIS_STREAM_SHARDS=5
KINESIS_STREAM_NAME=ai-study-tutor-kinesis-stream
awslocal kinesis create-stream --shard-count ${KINESIS_STREAM_SHARDS} \
  --stream-name ${KINESIS_STREAM_NAME}
set +x