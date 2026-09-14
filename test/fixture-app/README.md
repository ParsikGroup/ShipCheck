# Deliberately vulnerable fixture

**Do not deploy this. Do not copy from it.** Every file here is broken on
purpose so CI can prove shipcheck still detects each class of problem.

The credentials are non-functional placeholders. `AKIAIOSFODNN7EXAMPLE` is AWS's
own published documentation example; the rest are obvious fakes. None of them
work anywhere.

What is planted here, and which check should catch it:

| File | Planted problem |
|---|---|
| `src/routes/auth.js` | login/register/reset with no rate limiter; SQL string concatenation; password compared with `===`; no hashing library |
| `src/routes/upload.js` | file upload with no type, size or filename validation |
| `src/lib/supabase.js` | `service_role` key behind a `NEXT_PUBLIC_` prefix |
| `src/server.js` | wildcard CORS with credentials; routes with no auth checks |
| `.env.fixture` | secrets, including one behind a public prefix |
| `firestore.rules` | `allow read, write: if true` |

`test/run-fixture.sh` runs the whole pipeline against this and asserts every one
of them is found.
