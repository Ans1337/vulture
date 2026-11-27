# Fake internet: answers every DNS query with its own IP and every HTTP request with 200,
# logging all of it. Lives on an internal Docker network with no route out.
# Runs as non-root on a read-only rootfs with no capabilities; low ports are bound thanks to
# the namespaced sysctl net.ipv4.ip_unprivileged_port_start=0 set by the orchestrator.
FROM python:3.12-alpine
RUN adduser -D -H -u 1000 sink
COPY sinkhole.py /sinkhole.py
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
USER 1000:1000
CMD ["python", "/sinkhole.py"]
