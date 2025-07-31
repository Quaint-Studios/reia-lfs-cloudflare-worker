# Cloudflare Worker Git LFS Server

A simple, secure Git LFS server for Cloudflare Workers using R2 for storage and JWT authentication for uploads.

## Features

- **Public download:** Anyone can download LFS objects.
- **Authenticated upload:** Only users with a valid JWT token (present in a KV store) can upload.
- **Token management:** Generate and revoke tokens via API endpoints.
- **Git LFS Batch API:** Supports LFS batch operations for upload/download metadata.
- **CORS enabled:** Ready for cross-origin requests.

## Environment Variables

Bind these to your Worker:

- `LFS_ALLOWED_TOKENS`: KV namespace for allowed tokens.
- `LFS_JWT_SECRET`: Secret key for signing JWT tokens.  
  Generate with:  
  `node -e "console.log(require('crypto').randomBytes(64).toString('base64'));"`  
- `LFS_BUCKET`: R2 bucket for storing LFS objects.

## Endpoints

- `GET /lfs/objects/:oid`  
  Download an LFS object (public).
- `PUT /lfs/objects/:oid`  
  Upload an LFS object (requires Bearer JWT).
- `GET /generate`  
  Generate a JWT token (add it to KV manually).
- `POST /revoke`  
  Revoke a JWT token.
- `POST /objects/batch`  
  Git LFS Batch API (upload/download metadata).

## Usage Notes

- **Tokens:**  
  Generate with `/generate`, add to KV, and use as Bearer tokens for uploads.
- **Revocation:**  
  Remove from KV or use `/revoke` to block uploads with a token.
- **Customization:**  
  Change `REPO_URL`, `BUCKET_URL`, and `WORKER_URL` constants as needed.

---

MIT License  
Author: Quaint Studios,
