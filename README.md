# PathwayAI

**PathwayAI is an early-stage career/onboarding platform prototype** combining a user authentication API, a PostgreSQL data model for user profiles and document workflows, and Terraform definitions for an AWS application environment.

> **Project status:** Prototype / infrastructure and API components. This repository does not yet contain a complete, ready-to-deploy application.

## What is in this repository?

| Component | Current contents |
|---|---|
| Authentication API | Express routes for registration, login, token verification, and a basic token refresh example |
| Authentication security | Password hashing with bcrypt and JWT-based bearer authentication |
| Data model | PostgreSQL tables for users, conversations, documents, and OCR results |
| Cloud infrastructure | Terraform definitions for AWS networking, load balancing, ECS/Fargate, database/cache connectivity, and CloudWatch logging |

## Technology

- **API:** Node.js, Express
- **Authentication:** JSON Web Tokens, bcrypt
- **Database:** PostgreSQL, JSONB, UUID identifiers
- **Infrastructure:** Terraform, AWS provider
- **AWS building blocks:** VPC, public/private subnets, Application Load Balancer, ECS/Fargate, RDS/Redis-related security groups, and CloudWatch

## Repository structure

```text
PathwayAI/
├── Auth.js       # Express authentication API
├── Terraform.tf  # AWS infrastructure configuration
├── sql.dev       # PostgreSQL schema and timestamp triggers
└── README.md
```

## Authentication API

The current `Auth.js` file defines these routes:

| Method | Route | Purpose |
|---|---|---|
| POST | `/register` | Create or update a user password and issue a JWT |
| POST | `/login` | Verify credentials and issue a JWT |
| GET | `/me` | Return the authenticated user's account details |
| POST | `/refresh` | Demonstration token-refresh endpoint |

The API expects a PostgreSQL connection string in `DATABASE_URL` and a signing key in `JWT_SECRET`.

### Install dependencies

From the repository directory:

```bash
npm init -y
npm install express body-parser jsonwebtoken bcrypt pg dotenv
```

Set `DATABASE_URL` and `JWT_SECRET` in a local environment file before starting the API:

```bash
node Auth.js
```

The default port is `3001`; set `PORT` to override it.

## Database schema

The `sql.dev` schema defines:

- `users` — email, profile metadata, and onboarding state
- `conversations` — user-linked conversation records and message data
- `documents` — uploaded document metadata and processing state
- `ocr_results` — extracted text associated with documents

It also creates indexes for common user/conversation/document lookups and triggers to maintain `updated_at` timestamps.

## Infrastructure workflow

The Terraform configuration is parameterized for an AWS region, VPC CIDR ranges, subnet ranges, compute sizing, and container image. Review the full configuration before using it:

```bash
terraform fmt -check
terraform init
terraform validate
terraform plan
```

Do not apply the current configuration as-is. It contains development defaults that must be replaced, including a placeholder database password. Supply secrets securely, restrict inbound access, and verify all network and service dependencies before deployment.

## Security and production-readiness work

Before using this prototype with real users:

1. Require a strong externally supplied `JWT_SECRET`; remove the development fallback in the code.
2. Remove the default database password from Terraform and retrieve secrets from a managed secret store.
3. Add rate limiting, request validation, account recovery, and authentication tests.
4. Define a proper refresh-token lifecycle and revocation strategy.
5. Add upload validation, document storage controls, and access policies.
6. Add deployment automation, monitoring, and integration tests.

---

<p align="center"><i>Building the foundations for a more structured career journey.</i></p>
