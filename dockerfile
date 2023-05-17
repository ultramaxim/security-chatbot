FROM alpine:latest
ARG USERNAME=tgbot

RUN addgroup -S $USERNAME && adduser -S -G $USERNAME $USERNAME  && apk add python3  && apk add python3 py3-pip && pip3 install telebot requests
WORKDIR /home/tgbot
COPY . /home/tgbot
USER tgbot
CMD python3 main.py
