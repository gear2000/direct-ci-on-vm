FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install docker docker-compose git apt-transport-https wget apt-utils gnupg -y 

RUN apt-get install -y python3-pip python3-dev \
  && cd /usr/local/bin \
  && ln -s /usr/bin/python3 python \
  && pip3 install --upgrade pip

COPY requirements.txt requirements.txt

RUN pip3 install -r requirements.txt
COPY install_trivy_ubuntu.sh /opt/
COPY install-edreporterhelper.sh /opt/
RUN chmod 755 /opt/install_trivy_ubuntu.sh && chmod 755 /opt/install-edreporterhelper.sh 
RUN /opt/install_trivy_ubuntu.sh 
RUN /opt/install-edreporterhelper.sh
COPY bin /opt/

ENTRYPOINT ["python3"]
