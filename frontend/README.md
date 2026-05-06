# Personal Data Leak Dashboard

This frontend is a simple React dashboard for the Kubernetes-deployed Personal Data Leak Detector.

## Available sections
- Email Breach Scanner (`POST /scan/email`)
- GitHub Scanner (`POST /scan/github`)
- System Health Check (`GET /health`)

## Install

```bash
cd frontend
npm install
```

## Run

```bash
npm run dev
```

## Configure

Update `.env` with your EC2 NodePort API Gateway address:

```text
VITE_API_BASE_URL=http://<EC2-IP>:30007
```

The UI will call the API Gateway only, not individual microservices.
