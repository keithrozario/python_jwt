FROM ubuntu:latest
LABEL author="keith@keithrozario.com"

RUN apt-get update
RUN apt-get install -y python3-pip python3-dev libsasl2-dev libldap2-dev libssl-dev
RUN cd /usr/local/bin && \
    ln -s /usr/bin/python3 python
RUN pip3 install --upgrade pip 

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

WORKDIR /app
COPY ./requirements.txt /app
RUN pip3 install -r requirements.txt

COPY . /app

ENV FLASK_APP run.py
EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "run:app"]