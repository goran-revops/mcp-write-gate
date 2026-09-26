# Usage is in docs/security.md. "runner" runs the real servers and cannot read /gate; Node is for npx servers.
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends nodejs npm sudo \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 gate \
    && useradd --create-home --uid 10002 runner \
    && mkdir /gate && chown gate:gate /gate && chmod 700 /gate \
    && echo 'gate ALL=(runner) NOPASSWD:SETENV: ALL' > /etc/sudoers.d/mcp-write-gate \
    && echo 'Defaults:gate !requiretty' >> /etc/sudoers.d/mcp-write-gate \
    && chmod 440 /etc/sudoers.d/mcp-write-gate

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY mcp_write_gate ./mcp_write_gate
RUN pip install --no-cache-dir .

USER gate
ENV MCP_WRITE_GATE_HOME=/gate MCP_WRITE_GATE_CONFIG=/gate/gate.json MCP_WRITE_GATE_RUN_AS=runner
VOLUME /gate
EXPOSE 8765
ENTRYPOINT ["mcp-write-gate"]
CMD ["--help"]
