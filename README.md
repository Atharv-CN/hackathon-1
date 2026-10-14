# QShield on Vercel

This repository contains a Python Streamlit prototype in `qshield 2/`. Vercel cannot run that long-lived Streamlit application as an ordinary Vite project. The repository root now contains a browser version of the sender and receiver workflow. It builds to static assets and requires no server, database, environment variables, or account.

## Deploy from GitHub

1. In Vercel, choose **Add New → Project** and import `Atharv-CN/hackathon-1`.
2. Keep **Root Directory** at the repository root (`./`). The root `package.json` and `vercel.json` are the build entry points; do not select `qshield 2/`.
3. Framework preset: **Vite**. Build command: `npm run build`. Output directory: `dist`. Vercel should read these defaults from `vercel.json`.
4. Leave environment variables empty and deploy. Subsequent pushes to `main` deploy automatically after the change is merged.

To test locally, use Node 20.19 or newer:

```sh
npm ci
npm test
npm run build
npm run dev
```

## How it works

- The receiver generates an ML-KEM-768 key pair in the browser, shares the public key, and downloads an encrypted private key backup. A 64-byte seed is encrypted with PBKDF2-SHA256 and AES-256-GCM using the supplied password. It is never uploaded.
- The sender checks the public key fingerprint over a separate channel, encrypts a file, and downloads a `.qshield` package for manual delivery.
- The receiver restores the browser backup as needed, verifies and decrypts the package locally.
- The package format matches the Python QShield v1 format. A test decrypts the Python golden vector, and a separate interop check confirmed that Python can open a package produced in the browser.
- The Python app's encrypted PEM private keys use a different backup format. The web app does not import those PEM files. Use the Python app locally to open packages addressed to an existing PEM key.

**Security limits:** No sender authentication, key directory, network delivery, forward secrecy, or independent audit. The filename and size are visible in a package. Confirm public key fingerprints over another channel. This is a hackathon prototype, not a service for sensitive production data.

The older Streamlit app and its tests remain in `qshield 2/`. Its committed `venv/` is a generated local environment; new dependencies should be installed from requirements instead of committing a virtual environment.
