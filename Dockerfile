FROM python:3.11-slim

WORKDIR /workspace
COPY . /workspace
CMD ["./lab.sh", "help"]
