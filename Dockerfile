FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

WORKDIR /app

COPY pyproject.toml .
COPY auto_signin_http.py geetest_crack.py mousepath.json ./

RUN uv sync --frozen --no-dev

CMD ["uv", "run", "python", "auto_signin_http.py"]
