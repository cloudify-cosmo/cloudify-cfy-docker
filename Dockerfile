FROM ubuntu:16.04
RUN apt update
RUN apt-get -y install python-minimal
RUN apt-get -y install curl
RUN curl "https://bootstrap.pypa.io/get-pip.py" -o "get-pip.py"
RUN python get-pip.py
RUN pip install cloudify==5.0.5.1
