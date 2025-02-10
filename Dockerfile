FROM python:3.10

ENV PYTHONUNBUFFERED=1
ENV TERM=xterm-256color
ENV FORCE_COLOR=1

RUN apt-get update && apt-get install -y \
    build-essential \
    qtbase5-dev \
    qt5-qmake \
    qtchooser \
    bash

WORKDIR /app/

COPY requirements.txt requirements.txt

RUN pip3 install --upgrade pip setuptools wheel

RUN pip3 install --no-warn-script-location --no-cache-dir -r requirements.txt

COPY . .

CMD ["python3", "main.py", "-a", "1"]
