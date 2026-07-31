# AuthKit Testing & Deployment Workflows

This document explains how to configure, run, and test AuthKit across different environments:

1. **Local Development** (No Docker, No Nginx)
2. **Docker Development** (Docker containers with direct port exposure, No Nginx)
3. **Docker Production** (Docker containers behind Nginx reverse proxy)

---

## Environment Variable Reference

To test these environments, ensure you configure these variables inside your `.env` file correctly:

| Variable            | Description                                                                                                                        | Recommended (Local Dev) | Recommended (Production / Nginx) |
| :------------------ | :--------------------------------------------------------------------------------------------------------------------------------- | :---------------------- | :------------------------------- |
| `TRUST_PROXY`       | Determines if Express trusts incoming header chains (like `X-Forwarded-For`). Can be `true`, `false`, or a numeric number of hops. | `false`                 | `1` (or `true`)                  |
| `NGINX_SERVER_NAME` | The hostname Nginx checks for incoming connections (`server_name`). _Not used by backend application code._                        | `localhost`             | `authkit.yourdomain.com`         |
| `REDIS_PASSWORD`    | The password used by the backend client to authenticate with the Redis server.                                                     | `dev_redis_secure_pass` | `your_secure_prod_password`      |
| `REDIS_TLS`         | Controls whether transport layer security (TLS) is used for the Redis client connection (`true` / `false`).                        | `false`                 | `true` (if network requires it)  |

---

## 1. Local Development Workflow (No Docker, No Nginx)

In this setup, the API runs directly on your local operating system (e.g. via `pnpm dev`), communicating with local PostgreSQL and Redis servers.

```
[ Client / Postman / Swagger ] ──── (Port 8000) ────> [ Express API ]
```

### 1.1. Configuration (`.env`)

```ini
PORT=8000
NODE_ENV=development
TRUST_PROXY="false"
NGINX_SERVER_NAME="localhost"
```

### 1.2. Accessing Endpoints

- **API Base Url**: `http://localhost:8000/api/v1`
- **Swagger Documentation**: `http://localhost:8000/docs` (Fully functional out-of-the-box)
- **cURL Example**:
  ```bash
  curl -X POST http://localhost:8000/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@example.com","password":"yourpassword"}'
  ```

### 1.3. Email & Token Verification (Local Mailer)

- **Behavior**: Outbound emails are **not** sent via the Resend API when `NODE_ENV !== 'production'`.
- **Retrieval**: The mailer writes styled HTML email files to the host filesystem under the local **`tmp/`** directory (e.g. `tmp/test@example.com-verify_your_email_address.html`).
- **Testing**: Open the HTML file in your browser to copy OTP codes, click magic links, or verify email layouts. A valid `RESEND_API_KEY` is not required.

### 1.4. IP & Header Validation Behavior

- **Behavior**: Express ignores any incoming proxy headers like `X-Forwarded-For`.
- **Client IP**: The resolved client IP will be the raw socket address (`::1` or `127.0.0.1`).
- **Security**: IP or header spoofing has no effect, ensuring local rate-limiters are secure.

### 1.5. Redis & Database Access

- **Database**: Connect directly to PostgreSQL on your local host (usually port `5432`).
- **Redis**: Connect directly to Redis on `localhost:6379`.

---

## 2. Docker Development Workflow (With Docker, No Nginx)

In this environment, you run the database, caching services, and API inside Docker containers. The API container exposes its port (`8000`) directly to the host machine.

```
[ Client / Postman / Swagger ] ──── (Port 8000) ────> [ Docker API Container ]
```

### 2.1. Configuration (`.env`)

Ensure `docker-compose` maps the API port (e.g., `ports: - '8000:8000'`).

```ini
PORT=8000
NODE_ENV=development
TRUST_PROXY="false"
NGINX_SERVER_NAME="localhost"
```

### 2.2. Accessing Endpoints

- **API Base Url**: `http://localhost:8000/api/v1`
- **Swagger Documentation**: `http://localhost:8000/docs`
- **cURL Example**: Same as Local Development.

### 2.3. Email & Token Verification (Local Mailer)

- **Behavior**: Outbound emails are **not** sent via the Resend API when `NODE_ENV !== 'production'`.
- **Retrieval**: The mailer writes HTML emails inside the container under `/app/tmp/`.
- **Mounting**: Ensure your development `docker-compose` volume mounts `./tmp:/app/tmp` (host to container mapping). This lets you see and open the generated HTML files in the local `tmp/` folder on your host machine.
- **Testing**: Open the host's mapping folder to check the OTP/magic-link links.

### 2.4. IP & Header Validation Behavior

- **Behavior**: Since there is no reverse proxy container intercepting requests, Express reads incoming client socket connections directly.
- **Security**: `TRUST_PROXY` must remain `"false"`. If set to `"true"` without an Nginx gateway, an attacker could spoof `X-Forwarded-For` headers directly.

### 2.5. Redis & Database Access (Loopback Binding)

- **Database**: PostgreSQL container runs on the internal bridge network and maps port `5432` to host.
- **Redis Server**: Bound to the host loopback interface, accessible locally at `127.0.0.1:6379`.
- **Redis Insight UI**: Accessible on your local browser at `http://127.0.0.1:8001` or `http://localhost:8001`.
- **Authentication**: When connecting, you must supply the password configured in `REDIS_PASSWORD` (e.g. `dev_redis_secure_pass`).

---

## 3. Docker Production Workflow (With Nginx Gateway)

This is the standard production layout. The API container is isolated (no host port exposure) and can only be reached through the **Nginx reverse proxy container**, which maps host port `80` (and `443` for TLS).

```
[ Client / Postman / Swagger ] ─── (Port 80) ───> [ Nginx Container ] ─── (Internal Port 8000) ───> [ API Container ]
```

### 3.1. Configuration (`.env`)

```ini
PORT=8000
NODE_ENV=production
TRUST_PROXY="1"                  # Trusts Nginx as the single upstream proxy hop
NGINX_SERVER_NAME="localhost"    # Or your production domain, e.g. authkit.yourdomain.com
```

### 3.2. Accessing Endpoints

_Because traffic is routed through Nginx, you must make all requests on port `80` (not 8000)._

- **API Base Url**: `http://localhost/api/v1` (or `http://authkit.yourdomain.com/api/v1`)
- **Swagger Documentation**: `http://localhost/docs` (or `http://authkit.yourdomain.com/docs`)
- **cURL Example**:
  ```bash
  curl -X POST http://localhost/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@example.com","password":"yourpassword"}'
  ```

### 3.3. Email & Token Verification (Real Mailer)

- **Behavior**: Outbound emails are sent in real time to the user's inbox.
- **Integration**: The Resend API is active and requires a valid `RESEND_API_KEY` and verified domain in your `.env`.
- **Testing**: Check the real target inbox for verification links and OTPs.

### 3.4. IP & Header Validation Behavior

- **Behavior**: Nginx intercepts all client calls, strips client-supplied `X-Forwarded-For` headers, and creates a secure header chain with the true TCP source IP (`X-Real-IP`).
- **Security**: Express trusts this single hop (`TRUST_PROXY="1"`) and extracts the client IP safely from `req.ip` without risking IP spoofing.

### 3.5. Redis & Database Access (Isolated Setup)

- **Database**: PostgreSQL container is fully isolated and only accessible to backend containers inside the private bridge network.
- **Redis Server**: Maps no ports to the host machine (not even loopback), restricting connection paths to within the internal network.
- **Authentication**: The API container resolves and communicates with Redis internally using the credentials configured via `REDIS_PASSWORD`.
