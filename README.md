## Arika Authorization

`@arikajs/authorization` provides authorization (access control) for the ArikaJS framework.

It answers one critical question: **“Is the authenticated user allowed to perform this action?”**

This package provides a powerful authorization system with Gates and Policies, designed specifically for a modular, TypeScript-first Node.js framework.

---

### Status

- **Stage**: Experimental / v0.x
- **Scope**:
  - Gate-based authorization
  - Policy-based authorization
  - Authorization middleware
  - Centralized permission logic
- **Design**:
  - Framework-agnostic (usable outside HTTP layer)
  - Decoupled from transport layer
  - Type-safe APIs

---

## ✨ Purpose

Authorization is not authentication.

- **Authentication** → Who is the user? (Handled by `@arikajs/auth`)
- **Authorization** → What can the user do? (Handled by `@arikajs/authorization`)

This package works on top of `@arikajs/auth` but remains fully decoupled from it.

---

## 🚀 Features

- **Gate-based authorization**: Simple closure-based checks.
- **Policy-based authorization**: Organize logic per model/resource.
- **Middleware integration**: Protect routes easily.
- **Controller & service-level checks**: Call authorization logic from anywhere.
- **Type-safe APIs**: Built for TypeScript.
- **Framework-agnostic**: Can be used in CLI, WebSocket, or HTTP contexts.

---

## 📦 Installation

```bash
npm install @arikajs/authorization
# or
yarn add @arikajs/authorization
# or
pnpm add @arikajs/authorization
```

---

## 🧠 Core Concepts

### 1️⃣ Gates

Gates are simple ability checks defined globally.

```ts
import { Gate } from '@arikajs/authorization';

Gate.define('edit-post', (user, post) => {
  return user.id === post.userId;
});
```

**Usage:**

```ts
if (Gate.allows('edit-post', post)) {
  // ...
}

if (Gate.denies('edit-post', post)) {
  // ...
}
```

### 2️⃣ Policies

Policies organize authorization logic around a specific model or resource.

```ts
class PostPolicy {
  view(user, post) {
    return true;
  }

  update(user, post) {
    return user.id === post.userId;
  }
}
```

**Register Policy:**

```ts
Gate.policy(Post, PostPolicy);
```

**Usage:**

```ts
// Automatically resolves to PostPolicy.update
Gate.allows('update', post); 
```

### 3️⃣ Authorization Manager

The central engine that evaluates permissions.

```ts
const authz = new AuthorizationManager(user);

authz.can('edit-post', post);
authz.cannot('delete-post', post);
```

---

## 🧩 Middleware Support

Protect routes using authorization middleware:

```ts
Route.get('/posts/:id/edit', controller)
  .middleware('can:edit-post');
```

WITH arguments (e.g. Policies):

```ts
.middleware('can:update,post');
```

Middleware automatically:
1.  Resolves the authenticated user.
2.  Executes the authorization check.
3.  Throws `403 Forbidden` on failure.

---

## 🧑💻 Controller Usage

```ts
class PostController {
  update(request) {
    Gate.authorize('update', request.post);

    // Authorized logic proceeds here...
  }
}
```

If unauthorized, it throws an `AuthorizationException`, which is automatically handled by the HTTP layer.

---

## 🏗 Architecture

```
authorization/
├── src/
│   ├── Gate.ts                  ← Define & evaluate abilities
│   ├── AuthorizationManager.ts  ← Core authorization engine
│   ├── PolicyResolver.ts        ← Maps models to policies
│   ├── Middleware/
│   │   └── Authorize.ts         ← Route-level protection
│   ├── Exceptions/
│   │   └── AuthorizationException.ts
│   ├── Contracts/
│   │   └── Policy.ts
│   └── index.ts
├── package.json
├── tsconfig.json
├── README.md
└── LICENSE
```

---

## 🔌 Integration with ArikaJS

| Package | Responsibility |
| :--- | :--- |
| `@arikajs/auth` | User authentication |
| `@arikajs/authorization` | Access control |
| `@arikajs/router` | Route matching |
| `@arikajs/http` | Request & response handling |

---

## 🧪 Error Handling

Unauthorized access throws:
- `AuthorizationException` (403)

Handled automatically by:
- HTTP kernel
- Middleware pipeline

---

## 📌 Design Philosophy

- **Explicit over implicit**: Authorization rules should be clear.
- **Centralized rules**: Keep logic in Gates or Policies, not controllers.
- **Readable permission names**: Use descriptive names like `edit-post`.
- **Decoupled from transport layer**: Logic works for HTTP, CLI, etc.

> “Authentication identifies the user. Authorization empowers or restricts them.”

---

## 🔄 Versioning & Stability

- Current version: **v0.x** (Experimental)
- API may change until **v1.0**
- Will follow semantic versioning after stabilization

---

## 📜 License

`@arikajs/authorization` is open-sourced software licensed under the **MIT License**.
