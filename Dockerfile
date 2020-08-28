FROM centos:centos7
RUN yum -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm && \
    yum -y install sudo git ssh jq which && \
    yum clean all && \
    curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py && \
    python get-pip.py && \
    rm get-pip.py && \
    pip install --no-cache-dir cloudify==5.0.5.1 awscli && \
    rm -rf ~/.cache
COPY resources/cfyci.py /usr/local/bin/cfyci
