# CRM management and email two-factor

The Next.js application at E:\nestjs-auth-admin implements the supplied Admins/Roles/Users/Companies reference screens. Laravel is only a read-only reference; all changes are in the NestJS and Next.js repositories.

## Upgrade and run

```powershell
cd E:\nestjs-auth-foundation
npm run db:local
npm run db:migrate
npm run db:schema-check
npm run db:seed
npm run build
npm start
```

Start the frontend in a second terminal (`cd E:\nestjs-auth-admin`, `npm run dev`, or `npm run build` and `npm start`). Open http://localhost:3001/admins. The existing development admin remains admin@example.com / Admin@123456789!. Existing passwords are preserved.

Start `npm run mail:worker` in a third backend terminal. Development defaults to file delivery under `.local/mail`; inspect the newest matching `.eml` privately. Production requires SMTP configuration and a running worker. Do not enable email two-factor without operational delivery. SMS is deliberately unavailable until a provider is configured.

Migration 6 adds profile fields, guard metadata, company archival and login challenges. It preserves existing records; old roles default to the User guard. The explicit operator seed grants the new finite Admin/export/restore permissions to the seeded administrator. Other operators need deliberate delegation using existing policy management endpoints.

## Frontend behavior

- The sidebar has one User Management group: Admins, Roles, Users, Companies and the permission catalog. Navigation and actions use actual grants.
- Lists provide company filters for accounts, UTC created-date range, archived-record modes, guard filtering for roles, search, sortable columns, row selection, page size and first/previous/next/last pagination.
- CSV and genuine `.xlsx` downloads export the filtered result, up to 5000 records. Narrow filters above that limit. CSV text is protected against spreadsheet formula injection; XLSX uses literal string cells. Exports exclude passwords, tokens and avatar data.
- Create, view and edit are full pages. Account fields include photo, names, username, email, phone, date of birth, gender, company, roles, direct permissions and email preferences. Existing emails are read-only; passwords are entered only on creation and use the existing self-service lifecycle afterward. Date of birth, username, photo and company are optional; email, names and the initial confirmed password are required. Passwords require at least 15 characters.
- Avatars accept PNG/JPEG/WebP, crop client-side to a small JPEG and are validated on the backend. Maximum stored image size is 6KB. SVG is rejected.
- Role creation asks for a name and Admin/User guard; selecting the guard reveals grouped permissions. Select All affects delegable permissions only. Editing persists the complete direct permission selection atomically. Role inheritance remains separately controlled by the existing graph endpoints.
- Accounts and companies are archived on delete. Roles are permanently deleted. Restore does not restore old sessions. Restored accounts still need either mailbox verification or recorded admin approval, and remain subject to password-lock restrictions. Linked companies cannot be deleted until all accounts, including archived ones, are unlinked.
- Bulk operations are all-or-nothing, limited to 100 IDs and protected by the existing grant ceiling and last-recovery-manager invariant.

Theme settings and responsive behavior are shared with the existing Vristo shell. The default accent is teal; previously saved preferences take precedence. Navigation retains English/Urdu localization; the new detailed CRM forms and helper copy currently use English. User preferences never grant permissions.

## Backend contracts

All routes require live bearer authentication. Unsafe requests also require an allowed Origin. The Next.js same-origin API layer validates its HttpOnly session and permissions before forwarding to NestJS; NestJS repeats all authorization checks.

| Endpoint                                          | Behavior                                                          |
| ------------------------------------------------- | ----------------------------------------------------------------- |
| GET /api/v1/crm/:module                           | List, filter, sort and paginate                                   |
| GET /api/v1/crm/:module/:id                       | View a record; account results include direct role/permission IDs |
| POST /api/v1/crm/:module                          | Create Admin, User, Company or Role                               |
| PATCH /api/v1/crm/:module/:id                     | Update supported fields and optional direct grant sets            |
| POST /api/v1/crm/:module/bulk                     | `{ids: [uuid], action: "delete" or "restore"}`                    |
| GET /api/v1/crm/:module/export?format=csv or xlsx | Filtered export with separate permission                          |

Modules are allow-listed: `admins`, `users`, `companies`, `roles`, `permissions`. The permission catalog is read/export-only through CRM; creation keeps the existing `/authorization/permissions` contract. Permissions and roles cannot be restored after permanent deletion.

Queries: `page`, `limit` (1–100), `search`, `sortBy`, `sortOrder`, `companyId`, `fromDate`, `toDate`, `deleted=active|with|only`, `guard=admin|user`, `format=csv|xlsx`. Unsupported sort fields and invalid query values fail validation. Date ranges use inclusive UTC calendar days.

Permission requirements: module.read/create/update/delete, plus module.export or module.restore for the corresponding actions. Admins have independent `admins.*` permissions. Account `userType` separates Admin and User records; it does not confer access. The admin login additionally requires `admin.access`. Replacing role assignments requires roles.assign. Replacing a direct permission set requires permissions.assign and permissions.revoke. Creating roles also requires roles.delegate. Existing scopes and recovery-manager protections remain authoritative.

Role guards match the account type, including through the original role assignment endpoints. Inheritance cannot cross guards. Assigned roles cannot change guard until assignments and inheritance are removed. Permission catalogs are loaded across pages for the editor, up to 5000 entries; submitted grant arrays are limited to 100. The older dedicated user access screen still offers the original first-100 catalogs.

## Email verification and second-factor login

New managed accounts receive audited admin login approval and can sign in immediately with their email and initial password. Email ownership is not falsely marked verified: the verification email remains separate. Public registration still requires mailbox verification. Older pending managed records can be explicitly approved using Enable Login on the account page (requires module.update and the existing grant-scope checks). Admin account creation through the frontend preselects admin.access as a direct grant only when the creator can manage those grants; review it before saving. A role or account type alone never bypasses authorization.

1. Set Two-Factor to Email verification code for an account.
2. POST to the existing auth/login or auth/admin/login with valid credentials.
3. The response has `data.mfaRequired=true`, `challengeToken`, and `expiresIn=300`. It contains no access/refresh credentials and creates no session.
4. The encrypted durable outbox queues a six-digit code for the verified email. The worker delivers it.
5. POST `/api/v1/auth/login/verify` with `{challengeToken, code}`. Only successful verification issues the ordinary access token and HttpOnly refresh cookie.

The frontend keeps the challenge in a short-lived HttpOnly cookie and presents a six-digit-code step on the same login page. A reload resumes the step. Codes expire after five minutes, are single-use, allow at most five failed attempts and are invalidated by starting another sign-in. The database stores token/code digests; the email payload is encrypted. Completion rechecks account eligibility, the original password version and live admin permission. Changing a password, revoking admin access or deleting an account cannot be bypassed with a pending code. Email-based verification depends on mailbox security; SMS and authenticator-based enrollment are not implemented.

Notification preference stores the account's non-security channel choice (`none` or `email`). Required security/verification messages are always sent and are not muted by that setting. No unrelated business-notification feed is simulated.

## API client and validation

Reimport the updated Postman collection: 93 requests. Login scripts detect a pending second-factor challenge and save its token locally. Read the delivered code privately, set `verificationCode` and run Complete email two-factor login. No credentials or codes ship in the collection. CRUD and bulk examples should target disposable records deliberately.

Validation performed: 63 unit/infrastructure tests and 105 real PostgreSQL tests, plus 36 production-browser tests covering normal/admin login, email code completion, protected routes, permission matrix, profiles, CSV/XLSX downloads, archive/restore, mobile layouts and existing theme behavior. PostgreSQL test databases are separately owned disposable databases; the application database is not reset.

## Managed login approval (migration 7)

Admin-managed creation records accessApprovedAt and accessApprovedBy in the same transaction as the account and role grants. Public registration never receives approval. Authentication, JWT validation, refresh, password confirmation and recovery-manager invariants recognize this separate approval; inactive, archived and locked accounts remain blocked. Enable Login sends PATCH /api/v1/crm/users/:id (or admins/:id) with {"allowLogin":true}. It does not change passwords, roles or mailbox verification and cannot reactivate a suspended account. User records use Login as User; admin login still requires admin.access. An enabled email second factor remains mandatory and successful code verification also verifies that mailbox. Email-based recovery retains its verification requirements. No historical accounts are automatically approved by the migration.

## Extending the CRM

Register the entity, searchable fields, allowed sort fields and export columns in `src/features/crm/crm-modules.ts`. The list and export endpoints share this registry. Add the module’s validated write DTOs and service operations, define its permissions, and cover its allowed and denied operations in the PostgreSQL suite.
