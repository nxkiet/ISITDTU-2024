FROM ubuntu:24.04

RUN apt-get -y update && apt-get -y upgrade
RUN apt-get -y install build-essential socat libstdc++6 python3-pip

RUN ln -sf /usr/share/zoneinfo/Asia/Ho_Chi_Minh /etc/localtime && \
    echo "Asia/Ho_Chi_Minh" > /etc/timezone && \
    dpkg-reconfigure -f noninteractive tzdata

# Tạo người dùng 'ctf'
RUN useradd -ms /bin/bash ctf
WORKDIR /home/ctf

# Cấu hình giới hạn lệnh cho người dùng 'ctf'
RUN echo 'PATH=/bin:/usr/bin' > /home/ctf/.bashrc
RUN echo 'alias ls="ls --color=auto"' >> /home/ctf/.bashrc
RUN echo 'alias cat="cat"' >> /home/ctf/.bashrc
RUN echo 'alias cd="cd"' >> /home/ctf/.bashrc
RUN echo 'alias id="id"' >> /home/ctf/.bashrc
RUN echo 'export PATH' >> /home/ctf/.bashrc
RUN mkdir -p storage

# Copy các file vào container
COPY src/chall /home/ctf/
COPY src/ingredients /home/ctf/
COPY storage/ /home/ctf/storage/

# Cấp quyền sở hữu và quyền truy cập cho các file
RUN chown root:root /home/ctf/chall /home/ctf/ingredients
RUN chmod 550 /home/ctf
RUN chmod 775 /home/ctf/chall
RUN chmod u+s /home/ctf/chall
RUN chmod -R 755 storage/
RUN chmod 444 /home/ctf/ingredients

# Chuyển sang thư mục làm việc
WORKDIR /home/ctf

USER ctf
EXPOSE 12345

# Đảm bảo 'account' có thể thực thi
ENTRYPOINT ["sh", "-c", "exec socat -s TCP-LISTEN:12345,reuseaddr,fork EXEC:/home/ctf/chall,stderr,nofork"]