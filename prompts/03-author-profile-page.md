# Session 3: Author Profile Page on WritersProof Website

## Project
- Engine: `/Volumes/A/writerslogic` (Rust workspace)
- Website: `~/workspace_local/Writerslogic/writersproof` (React 19 + Vite, Hono.js API, Supabase, Cloudflare Workers)
- macOS app: `apps/cpoe_macos/` (SwiftUI)

Read CLAUDE.md and MEMORY.md for context.

## Prerequisites
Sessions 1 and 2 complete. Canonical fingerprint profile exists and syncs to Supabase.

## Goal
Build a user profile page at `/profile` on writersproof.com showing authorship fingerprint, writing stats, and an optional public shareable URL.

## Existing Infrastructure
- `author_fingerprints` table has `user_id`, `device_id`, `activity_summary` JSONB, `sample_count`, `confidence`, `quality_score`, `canonical_profile` JSONB (added in Session 2)
- `wp_certificates` table has certificate data per user
- `wp_sessions` table has session data per user
- `CloudSyncService.swift` uploads fingerprint data every 5 minutes
- `DashboardPage.tsx` is the auth-protected pattern to follow
- Auth is Supabase (JWT, `authMiddleware` in API)

## Part A: Anonymous Auth + Account Migration (macOS)

**Problem:** User installs app without creating account. Fingerprint data exists only locally until login.

**Solution:** Supabase anonymous sign-in on first launch, then link to real identity on signup.

1. **App launch, no session:** Call `supabase.auth.signInAnonymously()` — gives a real `user_id` for cloud sync.

2. **User signs UP (new account):** Call `supabase.auth.updateUser(UserAttributes(email:, password:))` — Supabase upgrades the anonymous user to authenticated. Same `user_id`, all data preserved. No migration needed.

3. **User signs IN (existing account from another device):** The anonymous `user_id` differs from the existing account. Need a merge endpoint.

**Requires:** Enable anonymous sign-ins in Supabase dashboard (Authentication > Settings).

**macOS changes:**
- `AuthService.swift`: On init, if no session, `signInAnonymously()`
- On sign-in (existing account): call `POST /v1/profile/merge-anonymous`

## Part B: API Endpoints (Hono.js)

New file: `apps/api/src/routes/profile.ts`

```typescript
// GET /v1/profile — authenticated user's full profile
// GET /v1/profile/:userId/public — public profile (no auth, only if opted in)
// PUT /v1/profile — upsert settings (display_name, public_profile_enabled, bio)
//   Uses upsert: INSERT on first access, UPDATE on subsequent — the user_profiles
//   row may not exist yet (e.g., anonymous user's first profile edit).
// POST /v1/profile/merge-anonymous — merge anonymous data into real account
```

**Response shape for `GET /v1/profile`:**
```typescript
interface ProfileResponse {
  user_id: string;
  display_name: string | null;
  member_since: string;
  public_profile_enabled: boolean;
  fingerprint: {
    confidence: number;
    sample_count: number;
    device_count: number;
    dimensions: Record<string, number>;
    maturity: "building" | "developing" | "mature" | "expert";
    last_updated: string;
  } | null;
  stats: {
    total_sessions: number;
    total_certificates: number;
    total_documents_witnessed: number;
    days_active: number;
  };
}
```

**Queries use PostgREST via `supabaseQuery` helper** (import from `../lib/supabase.js`):
```typescript
import { supabaseQuery, sanitizeParam } from '../lib/supabase.js';

// Fingerprint (best across devices)
const fps = await supabaseQuery<FingerprintRow[]>(c.env,
  `author_fingerprints?user_id=eq.${safeId}&select=confidence,sample_count,canonical_profile,updated_at&order=confidence.desc&limit=1`
);

// Certificate count
const certs = await supabaseQuery<CountRow[]>(c.env,
  `wp_certificates?user_id=eq.${safeId}&select=id`
);
const totalCerts = certs.length;

// Session count
const sessions = await supabaseQuery<CountRow[]>(c.env,
  `wp_sessions?user_id=eq.${safeId}&select=id`
);
const totalSessions = sessions.length;
```

Note: PostgREST doesn't support `COUNT(DISTINCT DATE(...))` directly. For `days_active`, fetch session `created_at` dates and deduplicate in JS, or use an RPC function.

**Register in `apps/api/src/index.ts`:**
```typescript
import { profileRoutes } from './routes/profile.js';
import { authMiddleware } from './middleware/auth.js';

app.use('/v1/profile', authMiddleware);  // auth required for own profile
app.use('/v1/profile/*', rateLimitMiddleware(30, 60));
app.route('/v1/profile', profileRoutes);
```

Note: `GET /v1/profile/:userId/public` is a sub-route under the same prefix but should NOT require auth. In the route handler, skip auth for that specific path — or register it on a separate prefix like `/v1/public-profile/:userId`.

**Merge endpoint** (`POST /v1/profile/merge-anonymous`):
- Takes `{ anonymous_token }` in body
- Verifies the anonymous token is valid and belongs to an anonymous user
- Copies `author_fingerprints` rows from anonymous `user_id` to authenticated `user_id`
- Merges canonical profiles (take highest confidence)
- Deletes anonymous user's data
- Returns `{ success: true, merged_samples: N }`

## Part C: Database Migration

New file: `supabase/migrations/YYYYMMDD_user_profiles.sql`

```sql
CREATE TABLE IF NOT EXISTS user_profiles (
    user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    display_name TEXT,
    bio TEXT,
    public_profile_enabled BOOLEAN DEFAULT FALSE,
    avatar_url TEXT,
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);
ALTER TABLE user_profiles ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users manage own profile" ON user_profiles
    FOR ALL USING (auth.uid() = user_id);

CREATE POLICY "Public profiles readable" ON user_profiles
    FOR SELECT USING (public_profile_enabled = true);
```

## Part D: Profile Page Frontend (React)

**Routes** (add to `App.tsx`):
```tsx
<Route path="/profile" element={<ProfilePage />} />
<Route path="/profile/:userId" element={<PublicProfilePage />} />
```

**Private Profile (`/profile`):**
1. Header: avatar + display name + member since + edit
2. Radar chart: 6 dimensions (typing_speed, consistency, pause_depth, correction_rate, zone_diversity, rhythm), SVG-based, ~280px
3. Maturity badge: "Building" / "Developing" / "Mature" / "Expert"
4. Stats grid: Sessions, Documents, Certificates, Days Active
5. Devices list (from `author_fingerprints` grouped by `device_id`)
6. Settings: display name (editable), public profile toggle, share link
7. Danger zone: delete account

**Public Profile (`/profile/:userId`):**
Minimal read-only: display name, confidence badge, session/document counts. NO detailed radar dimensions (privacy). "Verify a document" CTA.

**Radar chart component** (`components/RadarChart.tsx`):
```tsx
interface RadarChartProps {
  dimensions: { label: string; value: number }[]; // 0.0-1.0
  size?: number;
}
```
SVG hexagonal radar, gray reference lines at 25/50/75%, teal fill. Match existing dark theme.

**Data fetching:** Follow `DashboardPage` pattern — `useEffect` + `getSupabase().auth.getSession()` + fetch from API.

## Part E: Navigation + macOS Link

**Layout.tsx:** When authenticated, replace "Sign In" with avatar dropdown (Profile, Dashboard, Sign Out). Use `supabase.auth.onAuthStateChange` for reactivity.

**StyleFingerprintView.swift:** Add "View Online Profile" button that opens `https://writersproof.com/profile/{userId}` in browser. Only show when authenticated.

## Implementation Order
```
Part A (anon auth) ──┐
Part C (migration) ──┤── can parallelize
Part B (API) ────────┘── depends on C for table
Part D (frontend) ─────── depends on B for data
Part E (nav + macOS) ──── depends on D being deployed
```

## Edge Cases

| Scenario | Behavior |
|----------|----------|
| `/profile` without auth | Redirect to `/` |
| `/profile/:userId` non-existent | "Profile not found" |
| `/profile/:userId` private | "This profile is private" |
| User deletes account | CASCADE deletes all data, URL returns 404 |
| 0 samples | Empty radar + "Start using WritersProof" CTA |
| Multiple devices | Show highest-confidence fingerprint, list all devices |
| Toggle public off after sharing | Immediate, URL returns "private" |

## Constraints
- Follow existing code patterns in the writersproof repo
- Use `supabaseQuery` / `sanitizeParam` for database access (not raw SQL)
- Rate limit public endpoints
- RLS on all new tables
- Don't expose detailed typing patterns on public profiles (privacy)
