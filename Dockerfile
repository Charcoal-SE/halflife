FROM frolvlad/alpine-python3:latest

######## FIXME: replace dig (bind-tools) with dnspython
RUN apk add --no-cache git bind-tools && \
    : "install dependencies which need compilation from packages" && \
    apk add --no-cache py3-greenlet py3-gevent && \
    git clone https://github.com/tripleee/halflife.git && \
    git clone https://github.com/Charcoal-SE/SmokeDetector.git && \
    cd halflife && pip install -r requirements.txt && \
    pip install -r docker-requirements.txt && \
    rm -rf /var/cache/apk/* && \
    adduser -D halflife

ADD halflife.conf SmokeDetector/
ADD docker-run-halflife /hl

CMD ["/hl"]
