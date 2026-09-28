FROM python:3.11-alpine

WORKDIR /app

RUN apk add --no-cache nodejs npm
COPY server.py package.json package-lock.json /app/
COPY tools/ /app/tools/
RUN npm ci --omit=dev
RUN mkdir -p /app/public

EXPOSE 8088

CMD ["python", "server.py"]
