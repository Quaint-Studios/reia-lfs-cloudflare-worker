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
  Generate with `/generate`, add to KV, and use as Bearer tokens for uploads or a Basic token (guide below).
- **Revocation:**  
  Remove from KV or use `/revoke?key=<TOKEN>` to block uploads with a token.
- **Customization:**  
  Change `REPO_URL`, `BUCKET_URL`, and `WORKER_URL` constants as needed.

## Local Setup

### Configure LFS URL

Create a `.lfsconfig` file in your Git repository:

```ini
[lfs]
url = https://lfs.playreia.com/objects/batch
```
or set it globally
```sh
git config --global lfs.url https://lfs.playreia.com/objects/batch
```

### Authenticate for Uploads

You need a valid JWT token (from `/generate` and present in your KV store) for uploads.

**Option 1: Use** `git credentials approve`
Then paste this in there (make sure the change the JWT token):
```ini
protocol=https
host=lfs.playreia.com
username=whatever
password=YOUR_JWT_TOKEN_HERE
```

**Option 2: Add to** `.netrc`
On Linux: `~/.netrc`
On Windows: `%USERPROFILE%\.netrc`
```ini
machine lfs.playreia.com
login whatever
password YOUR_JWT_TOKEN_HERE
```

### Push and Pull
- **Push:** When you push, Git LFS will use your server for uploads and require your JWT token.
- **Pull/Clone:** When you pull or clone, Git LFS will fetch objects from your server (no token required).
---

MIT License  
Author: Quaint Studios, Kristopher Ali
