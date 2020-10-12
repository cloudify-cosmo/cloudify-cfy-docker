FROM centos:centos7.8.2003
RUN yum -y update && \
    yum -y install python2 git openssh-client curl gcc python2-devel make jq which unzip && \
    yum -y clean all && \
    curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && \
    python get-pip.py --no-cache-dir && \
    rm get-pip.py && \
    pip install --no-cache-dir cloudify==5.0.5.1 && \
    rm -rf ~/.cache
COPY resources/cfyci.py /usr/local/bin/cfyci
COPY resources/config.yaml /etc/cfyci/config.yaml
