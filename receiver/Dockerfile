FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1
WORKDIR /app

COPY common /common
COPY receiver/receiver.py .

EXPOSE 9001/udp 9101/tcp
CMD ["python", "receiver.py"]
