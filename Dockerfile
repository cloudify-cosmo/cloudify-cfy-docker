FROM alpine:3.12.0
RUN apk add --no-cache python2 git openssh-client curl gcc python2-dev musl-dev libffi-dev openssl-dev make jq && \
    curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && \
    python get-pip.py && \
    rm get-pip.py && \
    pip install --no-cache-dir cloudify==5.0.5.1 awscli && \
    rm -rf ~/.cache
COPY resources/cfyci.py /usr/local/bin/cfyci
