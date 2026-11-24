"""ASGI entry point: `uvicorn api.main:app --host 127.0.0.1` (make api). Read-only, bound to localhost."""

from __future__ import annotations

from api.app import create_app
from api.config import ApiConfig

app = create_app(ApiConfig())

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
