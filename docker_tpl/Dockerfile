FROM ubuntu:TAG
MAINTAINER ddaa
RUN apt-get update
RUN apt-get install xinetd -y
RUN apt-get install libc6-dev-i386 -y
RUN useradd -m ctf
RUN chmod 774 /tmp
RUN chmod -R 774 /var/tmp
RUN chmod -R 774 /dev
RUN chmod -R 774 /run
RUN chmod 1733 /tmp /var/tmp /dev/shm
RUN chown -R root:root /home/ctf
CMD ["/usr/sbin/xinetd","-dontfork"]
