FROM centos:7
RUN yum update -y
RUN yum -y install rubygems ruby-devel ruby-json gcc gcc-c++ python-setuptools rpm-build openssh-clients make
RUN gem install fpm
WORKDIR /src
