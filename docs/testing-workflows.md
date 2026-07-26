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

### Configuration (`.env`)

```ini
PORT=8000
NODE_ENV=development
TRUST_PROXY="false"
NGINX_SERVER_NAME="localhost"
```

### Accessing Endpoints

- **API Base Url**: `http://localhost:8000/api/v1`
- **Swagger Documentation**: `http://localhost:8000/docs` (Fully functional out-of-the-box)
- **cURL Example**:
  ```bash
  curl -X POST http://localhost:8000/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@example.com","password":"yourpassword"}'
  ```

### IP Validation Behavior

- Express ignores any incoming headers like `X-Forwarded-For`.
- The resolved client IP will be the raw socket address (`::1` or `127.0.0.1`).
- IP/Header spoofing has no effect, ensuring local brute force rate-limiters are secure.

---

## 2. Docker Development Workflow (With Docker, No Nginx)

In this environment, you run the database, caching services, and API inside Docker containers. The API container exposes its port (`8000`) directly to the host machine.

```
[ Client / Postman / Swagger ] ──── (Port 8000) ────> [ Docker API Container ]
```

### Configuration (`.env`)

Ensure `docker-compose` maps the API port (e.g., `ports: - '8000:8000'`).

```ini
PORT=8000
NODE_ENV=development
TRUST_PROXY="false"
NGINX_SERVER_NAME="localhost"
```

### Accessing Endpoints

- **API Base Url**: `http://localhost:8000/api/v1`
- **Swagger Documentation**: `http://localhost:8000/docs`
- **cURL Example**: Same as Local Development.

### IP Validation Behavior

- Since there is no reverse proxy container intercepting requests, Express reads incoming client socket connections directly.
- `TRUST_PROXY` must remain `"false"`. If set to `"true"` without an Nginx gateway, an attacker could spoof `X-Forwarded-For` headers directly.

### Accessing Redis & Redis Insight (Loopback Binding)

To inspect Redis data and access the **Redis Insight UI** during development, the ports in `docker-compose.dev.yml` are bound exclusively to the loopback interface (`127.0.0.1`):

- **Redis Server**: Accessible locally at `127.0.0.1:6379`.
- **Redis Insight UI**: Accessible on your local browser at `http://127.0.0.1:8001` or `http://localhost:8001`.
- **Authentication**: When connecting, you must supply the password configured in `REDIS_PASSWORD` (e.g. `dev_redis_secure_pass_1234`).
- **Internal Networking**: The API container and the Redis container communicate internally via the shared bridge network (`authkit_network`) using host alias `redis:6379`. The local loopback port exposure is for developer utility only and does not affect container-to-container traffic.

---

## 3. Docker Production Workflow (With Nginx Gateway)

This is the standard production layout. The API container is isolated (no host port exposure) and can only be reached through the **Nginx reverse proxy container**, which maps host port `80` (and `443` for TLS).

```
[ Client / Postman / Swagger ] ─── (Port 80) ───> [ Nginx Container ] ─── (Internal Port 8000) ───> [ API Container ]
```

### Configuration (`.env`)

```ini
PORT=8000
NODE_ENV=production
TRUST_PROXY="1"                  # Trusts Nginx as the single upstream proxy hop
NGINX_SERVER_NAME="localhost"    # Or your production domain, e.g. authkit.yourdomain.com
```

### Accessing Endpoints

_Because traffic is routed through Nginx, you must make all requests on port `80` (not 8000)._

- **API Base Url**: `http://localhost/api/v1` (or `http://authkit.yourdomain.com/api/v1`)
- **Swagger Documentation**: `http://localhost/docs` (or `http://authkit.yourdomain.com/docs`)
- **cURL Example**:
  ```bash
  curl -X POST http://localhost/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@example.com","password":"yourpassword"}'
  ```

### Swagger Compatibility

- Swagger UI works perfectly because it initiates requests relative to the window origin (`http://localhost/docs` triggers `http://localhost/api/v1/...`).
- CORS allowed origins automatically accept your domain host since it is configured under `FRONTEND_ORIGINS` or `DOMAIN_URL`.

### IP Validation Behavior

- Nginx intercepts all client calls, strips any client-supplied `X-Forwarded-For` headers, and creates a secure header chain with the true TCP source IP (`X-Real-IP`).
- Express trusts this single hop (`TRUST_PROXY="1"`) and extracts the client IP safely from `req.ip` without risking IP spoofing.

### Accessing Redis (Isolated Setup)

In the production layout, Redis is fully isolated:

- **No Port Exposures**: The `redis` service maps no ports to the host machine (not even loopback), restricting connection paths to within the internal `authkit_network` bridge.
- **Internal Only**: The API container resolves and communicates with Redis internally using the credentials configured via `REDIS_PASSWORD`.
- **Debugging**: If troubleshooting is required on production environments, you can map the ports temporarily or use port-forwarding via SSH (e.g., `ssh -L 6379:redis:6379`).
