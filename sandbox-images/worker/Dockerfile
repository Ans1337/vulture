# Detonation worker: fetches the target, scans it statically, then runs it under
# strace + libfaketime with honeytokens planted. One container per stage per scan.
FROM node:20-bookworm-slim AS node

FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
      strace faketime git ca-certificates python3 tini \
    && rm -rf /var/lib/apt/lists/* \
    && ln -s "$(dpkg -L libfaketime | grep 'libfaketime.so.1$' | head -1)" /usr/local/lib/libfaketime.so.1
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
    && mkdir -p /work && chown ubuntu:ubuntu /work
COPY *.py /opt/scan/
RUN chmod -R a+rX /opt/scan
ENV NPM_CONFIG_UPDATE_NOTIFIER=false NPM_CONFIG_AUDIT=false NPM_CONFIG_FUND=false PYTHONUNBUFFERED=1 PYTHONPATH=/opt/scan
# Unprivileged user (uid 1000) that ships with the Ubuntu image.
USER ubuntu
WORKDIR /work
ENTRYPOINT ["/usr/bin/tini", "--", "python3"]
