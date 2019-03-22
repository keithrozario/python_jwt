#! /bin/bash
ssh-keygen -t rsa -b 4096 -m PEM -f jwtRS256.pem
openssl rsa -in jwtRS256.pem -pubout -outform PEM -out jwtRS256.key.pub

