# Fake internet: answers every DNS query with its own IP and every HTTP request with 200,
# logging all of it. Lives on an internal Docker network with no route out.
FROM python:3.12-alpine
COPY sinkhole.py /sinkhole.py
ENV PYTHONUNBUFFERED=1
CMD ["python", "/sinkhole.py"]
