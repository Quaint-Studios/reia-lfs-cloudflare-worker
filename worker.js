/// Cloudflare Worker for Git LFS Server with R2 and JWT Authentication
/// Author: Quaint Studios, Kristopher Ali
/// License: MIT
/// How to configure: https://github.com/Quaint-Studios/reia-lfs-cloudflare-worker/blob/main/README.md

// Define the Git LFS content type
const LFS_CONTENT_TYPE = 'application/vnd.git-lfs+json';
const REPO_URL = 'https://github.com/quaint-studios/reia';
const BUCKET_URL = 'https://r2.lfs.playreia.com';
const WORKER_URL = 'https://lfs.playreia.com';

const corsHeaders = {
	'Access-Control-Allow-Origin': '*',
	'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS',
	'Access-Control-Allow-Headers': 'Authorization, Content-Type'
};

/**
 * @typedef {Object} Env
 * @property {KVNamespace} LFS_ALLOWED_TOKENS
 * @property {string} LFS_JWT_SECRET
 * @property {R2Bucket} LFS_BUCKET
 */

export default {
	/**
	 * @param {Request} request
	 * @param {Env} env
	 * @param {ExecutionContext} ctx
	 */
	async fetch(request, env, ctx) {
		return handleRequest(request, env);
	}
}

/**
 * @param {Request} request - The incoming request object
 * @param {Env} env - Environment bindings (KV, secrets, etc.)
 * @returns {Promise<Response>}
 */
async function handleRequest(request, env) {
	const url = new URL(request.url);
	const path = url.pathname.replace(/\/+$/, '') || '/';
	const method = request.method;

	// Handle CORS preflight for all routes
	if (method === 'OPTIONS') {
		return new Response(null, { status: 204, headers: corsHeaders });
	}

	// Convert JWT_SECRET to a Uint8Array for signing/verification
	const secretKey = new TextEncoder().encode(env.LFS_JWT_SECRET);
	try {
		// Match /lfs/objects/:oid for GET (download) and PUT (upload)
		if (path.startsWith('/lfs/objects/')) {
			const oid = path.split('/').pop(); // Get the last segment as OID

			// Validate OID format
			if (!isValidOid(oid)) {
				return new Response(JSON.stringify({ error: 'Invalid OID format.' }), {
					status: 400,
					headers: { 'Content-Type': 'application/json', ...corsHeaders }
				});
			}

			return await handleObjectRequest(request, env, secretKey, oid);
		}

		switch (path) {
			case '/generate':
				// Handle token generation
				if (method === 'GET') {
					const tokenResponse = await generateToken(secretKey);
					// generateToken now returns a JSON string, so we set the Content-Type

					// This is set in the KV Store manually. It's never set automatically.
					return new Response(tokenResponse, { status: 200, headers: { 'Content-Type': 'application/json' } });
				}
				break;
			case '/revoke':
				// Handle token revocation via POST body or GET query parameter
				if (method === 'POST' || method === 'GET') {
					const revokeResponse = await revokeToken(request, secretKey, env);
					return new Response(revokeResponse, { status: 200, headers: { 'Content-Type': 'application/json' } });
				}
				break;
			case '/objects/batch':
				// Handle Git LFS Batch requests (upload/download metadata)
				if (method === 'POST') {
					const batchResponse = await handleBatchRequest(request, env, secretKey); // Implementing soon. Ignore.
					return new Response(batchResponse, { status: 200, headers: { 'Content-Type': LFS_CONTENT_TYPE, ...corsHeaders } });
				}
				break;
			default:
				return new Response('Not Found', { status: 404, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
		}

		return new Response('Method Not Allowed', { status: 405, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
	} catch (err) {
		return new Response(JSON.stringify({ error: err.message || 'Internal Server Error' }), { status: 500, headers: { 'Content-Type': 'application/json', ...corsHeaders } });
	}
}

// Utility function to generate a cryptographically random hexadecimal string for token IDs
function generateRandomId(byteLength = 16) { // 16 bytes will result in a 32-character hex string
	const randomBytes = new Uint8Array(byteLength);
	crypto.getRandomValues(randomBytes); // Fill the buffer with cryptographically random values

	// Convert each byte to its two-digit hexadecimal representation
	return Array.from(randomBytes)
		.map(b => b.toString(16).padStart(2, '0'))
		.join('');
}


/**
 * Generates a JWT token string which should be added in manually to the KV store.
 * @param {Request} request The incoming request.
 * @param {Uint8Array} secretKey The JWT secret key as a Uint8Array.
 * @returns {Promise<string>} The generated JWT token string (JSON format).
 */
async function generateToken(secretKey) {
	try {
		const tokenId = generateRandomId();

		const payload = {
			'urn:admin': false,
			'tokenId': tokenId,
			'iss': WORKER_URL,
			'aud': REPO_URL
		};

		const jwt = await signJwt(payload, secretKey);

		return JSON.stringify({ tokenId, token: jwt });
	} catch (e) {
		console.error('Error generating token:', e);
		return JSON.stringify({ error: `Error generating token: ${e.message}` });
	}
}

/**
 * Signs a JWT payload using HS256 with the Web Crypto API.
 * @param {object} payload - The JWT payload to sign.
 * @param {Uint8Array} secretKey - The secret key as a Uint8Array.
 * @returns {Promise<string>} The signed JWT string.
 */
async function signJwt(payload, secretKey) {
	const header = {
		alg: 'HS256',
		typ: 'JWT'
	};

	// Encode header and payload to Base64Url
	const encodedHeader = btoa(JSON.stringify(header))
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=+$/, '');
	const encodedPayload = btoa(JSON.stringify(payload))
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=+$/, '');

	const dataToSign = `${encodedHeader}.${encodedPayload}`;

	const key = await crypto.subtle.importKey(
		'raw',
		secretKey,
		{ name: 'HMAC', hash: 'SHA-256' },
		false,
		['sign']
	);

	const signature = await crypto.subtle.sign(
		'HMAC',
		key,
		new TextEncoder().encode(dataToSign)
	);

	const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signature)))
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=+$/, '');

	return `${dataToSign}.${encodedSignature}`;
}

/**
 * Verifies a JWT token using HS256 with the Web Crypto API.
 * @param {string} token - The JWT token string.
 * @param {Uint8Array} secretKey - The secret key as a Uint8Array.
 * @returns {Promise<object|null>} The decoded payload if valid, otherwise null.
 */
async function verifyJwt(token, secretKey) {
	const parts = token.split('.');
	if (parts.length !== 3) {
		return null; // Invalid JWT format
	}

	const encodedHeader = parts[0];
	const encodedPayload = parts[1];
	const encodedSignature = parts[2];

	const dataToVerify = `${encodedHeader}.${encodedPayload}`;

	// Convert Base64Url signature back to ArrayBuffer for verification
	const signatureBuffer = new Uint8Array(
		atob(encodedSignature.replace(/-/g, '+').replace(/_/g, '/')).split('').map(c => c.charCodeAt(0))
	);

	const key = await crypto.subtle.importKey(
		'raw',
		secretKey,
		{ name: 'HMAC', hash: 'SHA-256' },
		false,
		['verify']
	);

	const isValid = await crypto.subtle.verify(
		'HMAC',
		key,
		signatureBuffer,
		new TextEncoder().encode(dataToVerify)
	);

	if (!isValid) {
		return null; // Signature invalid
	}

	try {
		// Decode payload from Base64Url
		const payloadString = atob(encodedPayload.replace(/-/g, '+').replace(/_/g, '/'));
		const payload = JSON.parse(payloadString);

		return payload;
	} catch (e) {
		console.error('Error parsing JWT payload:', e);
		return null; // Malformed payload
	}
}

/**
 * Handles the token revocation request.
 * @param {Request} request The incoming request.
 * @param {Uint8Array} secretKey The JWT secret key as a Uint8Array.
 * @param {Env} env The environment variables (to access ALLOWED_TOKENS KV).
 * @returns {Promise<string>} An empty string for now.
 */
async function revokeToken(request, secretKey, env) {
	let tokenToRevoke = '';
	if (request.method === 'GET') {
		const url = new URL(request.url);
		tokenToRevoke = url.searchParams.get('key');
	} else if (request.method === 'POST') {
		tokenToRevoke = await request.text();
	}

	if (!tokenToRevoke) {
		return JSON.stringify({ error: 'Token to revoke is missing.' });
	}

	try {
		const payload = await verifyJwt(tokenToRevoke, secretKey);

		if (!payload || !payload.tokenId) {
			return JSON.stringify({ error: 'Invalid token or token ID missing in payload.' });
		}

		const tokenId = payload.tokenId;

		if (env.LFS_ALLOWED_TOKENS) {
			const existingToken = await env.LFS_ALLOWED_TOKENS.get(tokenId);
			if (existingToken) {
				await env.LFS_ALLOWED_TOKENS.delete(tokenId);
				return JSON.stringify({ message: `Token with ID '${tokenId}' received.` });
			} else {
				// Don't tell them if it worked or not.
				return JSON.stringify({ message: `Token with ID '${tokenId}' received.` });
			}
		} else {
			console.warn('ALLOWED_TOKENS KV binding not found. Cannot revoke token.');
			return JSON.stringify({ error: 'KV store not available for revocation.' });
		}
	} catch (e) {
		console.error('Error revoking token:', e);
		return JSON.stringify({ error: `Error revoking token: ${e.message}` });
	}
}


/**
 * Handles requests to the /lfs/objects/:oid endpoint for GET (download) and PUT (upload) operations.
 * 
 * - Requires a valid Bearer JWT token in the Authorization header.
 * - For GET: Retrieves the object with the given OID from the R2 bucket and returns it as an octet-stream.
 * - For PUT: Uploads the request body as the object with the given OID to the R2 bucket.
 * - Responds with appropriate CORS headers for all responses.
 * 
 * @param {Request} request - The incoming HTTP request.
 * @param {Env} env - The environment bindings, including the R2 bucket and secrets.
 * @param {Uint8Array} secretKey - The JWT secret key as a Uint8Array.
 * @param {string} oid - The object ID (OID) from the URL path.
 * @returns {Promise<Response>} - The HTTP response for the object operation.
 */
async function handleObjectRequest(request, env, secretKey, oid) {
	const method = request.method;

	// Always set CORS headers
	const baseHeaders = { ...corsHeaders };

	if (method === 'GET') {
		// Download object from R2
		try {
			const obj = await env.LFS_BUCKET.get(lfsObjectPath(oid));
			if (!obj) {
				return new Response(JSON.stringify({ error: 'Object not found.' }), {
					status: 404,
					headers: baseHeaders
				});
			}
			const headers = {
				...baseHeaders,
				'Content-Type': 'application/octet-stream'
			};
			if (typeof obj.size === 'number') {
				headers['Content-Length'] = obj.size;
			}
			return new Response(obj.body, { status: 200, headers });
		} catch (e) {
			return new Response(JSON.stringify({ error: 'Error reading object.' }), {
				status: 500,
				headers: baseHeaders
			});
		}
	} else if (method === 'PUT') {
		// Require Authorization header with Bearer token
		const authHeader = request.headers.get('Authorization');
		if (!authHeader || (!authHeader.startsWith('Bearer ') && !authHeader.startsWith('Basic '))) {
			return new Response(JSON.stringify({ error: 'Missing or invalid Authorization header.' }), {
				status: 401,
				headers: baseHeaders
			});
		}
		let token = null;
		if (authHeader.startsWith('Basic ')) {
			const decoded = atob(authHeader.slice('Basic '.length));
			token = decoded.split(':')[1].trim();
		} else if (authHeader.startsWith('Bearer ')) {
			token = authHeader.slice('Bearer '.length).trim();
		}

		if (!token) {
			return new Response(JSON.stringify({ error: 'Missing token in Authorization header.' }), {
				status: 401,
				headers: baseHeaders
			});
		}

		const payload = await verifyJwt(token, secretKey);
		if (!payload || !payload.tokenId) {
			return new Response(JSON.stringify({ error: 'Invalid or expired token.' }), {
				status: 401,
				headers: baseHeaders
			});
		}

		const allowed = await env.LFS_ALLOWED_TOKENS.get(payload.tokenId);
		if (!allowed) {
			return new Response(JSON.stringify({ error: 'Token is not allowed or has been revoked.' }), {
				status: 401,
				headers: baseHeaders
			});
		}

		// Upload object to R2
		try {
			const contentLength = request.headers.get('Content-Length');
			if (!contentLength) {
				return new Response(JSON.stringify({ error: 'Content-Length required.' }), {
					status: 411,
					headers: baseHeaders
				});
			}
			const putRes = await env.LFS_BUCKET.put(lfsObjectPath(oid), request.body);
			return new Response(null, { status: 200, headers: baseHeaders });
		} catch (e) {
			return new Response(JSON.stringify({ error: 'Error uploading object.' }), {
				status: 500,
				headers: baseHeaders
			});
		}
	} else {
		return new Response('Method Not Allowed', { status: 405, headers: baseHeaders });
	}
}

/**
 * Handles Git LFS Batch API requests.
 * @param {Request} request
 * @param {Env} env
 * @param {Uint8Array} secretKey
 * @returns {Promise<string>} JSON string for LFS batch response
 */
async function handleBatchRequest(request, env, secretKey) {
	// Parse the LFS batch request body
	let body;
	try {
		body = await request.json();
	} catch {
		return JSON.stringify({ message: 'Invalid JSON body.' });
	}

	const operation = body.operation || "download";
	const objects = Array.isArray(body.objects) ? body.objects : [];

	let token = null;
	let payload = null;

	if (operation === "upload") {
		// Parse Authorization header for JWT
		const authHeader = request.headers.get('Authorization');
		if (!authHeader || (!authHeader.startsWith('Bearer ') && !authHeader.startsWith('Basic '))) {
			return JSON.stringify({ message: 'Missing or invalid Authorization header.' });
		}
		if (authHeader.startsWith('Basic ')) {
			const decoded = atob(authHeader.slice('Basic '.length));
			token = decoded.split(':')[1].trim();
		} else if (authHeader.startsWith('Bearer ')) {
			token = authHeader.slice('Bearer '.length).trim();
		}

		if (!token) {
			return JSON.stringify({ message: 'Missing token in Authorization header.' });
		}

		payload = await verifyJwt(token, secretKey);
		if (!payload || !payload.tokenId) {
			return JSON.stringify({ message: 'Invalid or expired token.' });
		}

		const allowed = await env.LFS_ALLOWED_TOKENS.get(payload.tokenId);
		if (!allowed) {
			return JSON.stringify({ error: 'Token is not allowed or has been revoked.' });
		}
	}

	// Prepare response objects
	const results = [];
	for (const obj of objects) {
		const oid = obj.oid;

		// Validate OID format
		if (!isValidOid(oid)) {
			results.push({
				oid,
				size: obj.size,
				error: {
					code: 400,
					message: "Invalid OID format"
				}
			});
			continue;
		}

		const size = obj.size;

		// Check if object exists in R2
		let exists = false;
		try {
			if (env.LFS_BUCKET) {
				const r2obj = await env.LFS_BUCKET.head(lfsObjectPath(oid));
				exists = !!r2obj;
			}
		} catch (e) {
			// If R2 errors, treat as missing
			exists = false;
		}

		if (operation === "download") {
			if (exists) {
				// Provide download action
				results.push({
					oid,
					size,
					actions: {
						download: {
							href: `${BUCKET_URL}/${lfsObjectPath(oid)}`
						}
					}
				});
			} else {
				// Object missing
				results.push({
					oid,
					size,
					error: {
						code: 404,
						message: "Object does not exist"
					}
				});
			}
		} else if (operation === "upload") {
			if (!token) {
				return JSON.stringify({ message: 'Upload operation requires a valid token.' });
			}

			if (!exists) {
				results.push({
					oid,
					size,
					actions: {
						upload: {
							href: `${WORKER_URL}/${lfsObjectPath(oid)}`,
							header: {
								Authorization: `Bearer ${token}`
							}
						}
					}
				});
			} else {
				results.push({
					oid,
					size,
					error: {
						code: 409,
						message: "Object already exists"
					}
				});
			}
		} else {
			results.push({
				oid,
				size,
				error: {
					code: 501,
					message: "Only download and upload operations are supported"
				}
			});
		}
	}

	return JSON.stringify({
		transfer: 'basic',
		objects: results
	});
}

/** * Generates the object key for R2 storage based on the OID.
 * The key is structured as lfs/objects/{first2}/{next2}/{rest}
 * where first2 and next2 are the first two characters of the OID.
 * @param {string} oid - The object ID (OID) to generate the key for.
 * @returns {string} The generated object key.
 */
function lfsObjectPath(oid) {
	const first2 = oid.slice(0, 2);
	const next2 = oid.slice(2, 4);
	const rest = oid.slice(4);
	return `lfs/objects/${first2}/${next2}/${rest}`;
}

/** * Validates if the given OID is a valid Git LFS object ID.
 * A valid OID is a 64-character hexadecimal string.
 * @param {string} oid - The object ID to validate.
 * @returns {boolean} True if valid, false otherwise.
 */
function isValidOid(oid) {
	if (oid.length !== 64 || oid.includes('/') || oid.includes('\\')) return false;
	for (let i = 0; i < 64; i++) {
		const c = oid[i];
		if (
			!((c >= 48 && c <= 57) // 0-9
				|| (c >= 97 && c <= 102) // a-f
				|| (c >= 65 && c <= 70) // A-F
			)
		) {
			return false;
		}
	}
	return true;
}
