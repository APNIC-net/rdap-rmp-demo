FROM ubuntu:18.04

RUN apt-get update -y
RUN apt-get install -y \
    libhttp-daemon-perl \
    libwww-perl \
    libcarp-always-perl \
    libnet-ip-perl \
    libjson-xs-perl \
    libnet-ip-xs-perl \
    libset-intervaltree-perl \
    libnet-patricia-perl \
    cpanminus \
    gcc \
    make
RUN cpanm \
    Crypt::JWT
RUN apt-get install -y \
    curl
COPY . /root/rdap-rmp-demo
RUN cd /root/rdap-rmp-demo/ && perl Makefile.PL && make && make test && make install
RUN rm -rf /root/rdap-rmp-demo/
