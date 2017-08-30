FROM frolvlad/alpine-python3:latest

######## FIXME: replace dig (bind-tools) with dnspython
RUN apk add --no-cache git bind-tools && \
    : "install dependencies which need compilation from packages" && \
    apk add --no-cache py3-greenlet py3-gevent && \
    adduser -D halflife && \
    su - halflife sh -c '\
        set -eu && \
        git clone https://github.com/tripleee/halflife.git && \
        git clone https://github.com/Charcoal-SE/SmokeDetector.git' && \
    cd /home/halflife/halflife && pip install -r requirements.txt && \
        pip install -r docker-requirements.txt && \
    rm -rf /var/cache/apk/*

ADD halflife.conf /home/halflife/SmokeDetector/
ADD docker-run-halflife /hl
ADD docker-cron-15min /etc/periodic/15min/git-pull-sd
######## TODO: package as an apk package
# https://github.com/tripleee/websocketd-alpine
ADD websocketd /usr/local/bin

EXPOSE 8888

CMD ["/hl"]
