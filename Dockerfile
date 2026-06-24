FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ERASEKEY_PUBLIC_DEMO_MODE=true \
    ERASEKEY_KMS_MODE=mock \
    ERASEKEY_DB_PATH=/tmp/erasekey/erasekey.db \
    ERASEKEY_RECEIPT_LOG_PATH=/tmp/erasekey/deletion_receipts.jsonl \
    ERASEKEY_RECEIPT_SIGNING_KEY_PATH=/tmp/erasekey/.receipt_signing_key

WORKDIR /app

COPY mvp/erasekey/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY mvp/erasekey/ .

RUN useradd --create-home --uid 10001 erasekey \
    && mkdir -p /tmp/erasekey \
    && chown -R erasekey:erasekey /app /tmp/erasekey

USER erasekey

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
