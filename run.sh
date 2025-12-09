#!/bin/bash

docker build -t sshs_asg2 -f Dockerfile .
docker run -it sshs_asg2 \
    python3 asg2.py 
