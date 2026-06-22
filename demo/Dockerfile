# Standalone fake-vulnerable LiteLLM target (CVE-2026-42208 stub).
# Stdlib-only Python, so the slim base needs no extra installs. This image is
# usable on its own, but in docker-compose.demo.yml the same script is baked
# into the agent image and run there so the agent and target share a network
# namespace (see agent/Dockerfile / docker-entrypoint.sh).
FROM python:3.12-slim

WORKDIR /app
COPY fake_litellm.py .

EXPOSE 4000

CMD ["python", "fake_litellm.py"]
