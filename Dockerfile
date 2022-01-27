FROM centos:centos7.8.2003
RUN yum -y update && \
    yum -y install python3 git curl gcc python3-devel make jq which unzip && \
    yum -y clean all && \
    curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && \
    python3 get-pip.py --no-cache-dir && \
    rm -f get-pip.py && \
    pip install --no-cache-dir cloudify==6.2.0 && \
    rm -rf ~/.cache && \
    set -x && \
    printenv
COPY resources/cfyci.py /usr/local/bin/cfyci
COPY resources/config.yaml /etc/cfyci/config.yaml
