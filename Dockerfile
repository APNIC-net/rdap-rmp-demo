FROM ubuntu:18.04

RUN apt-get update -y
RUN apt-get install -y \
    libhttp-daemon-perl \
    libio-capture-perl \
    libwww-perl \
    libcarp-always-perl \
    libnet-ip-perl \
    libjson-xs-perl \
    libnet-ip-xs-perl \
    libset-intervaltree-perl \
    libnet-patricia-perl \
    cpanminus \
    gcc \
    curl \
    jq \
    make
RUN cpanm \
    Crypt::JWT
COPY . /root/rdap-rmp-demo
RUN cd /root/rdap-rmp-demo/ && perl Makefile.PL && make && make test && make install
RUN cp -r /root/rdap-rmp-demo/eg /
RUN rm -rf /root/rdap-rmp-demo/
