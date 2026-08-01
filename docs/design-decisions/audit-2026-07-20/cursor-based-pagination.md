# Design Decision Record: Cursor-Based Pagination

## Context & Problem Statement

The listing endpoints `/api/v1/admin/users`, `/api/v1/session` (current user's sessions), and `/api/v1/admin/sessions/user/:userId` (an admin's view of user sessions) originally executed unbounded database queries (`findMany`) without limits or pagination (Audit Ref: [July 2026 Performance Audit - M-1](../../audit/2026-07-20/performance.md#m-1---no-pagination-on-list-endpoints)).

As the database grows:

1.  **Memory Bloat**: Fetching and serializing thousands of users/sessions simultaneously saturates Node.js runtime memory, network transit limits, and database memory.
2.  **Unbounded Payloads**: Exposed endpoints are vulnerable to DoS attacks by making requests that force massive serialization loads.

Traditional **Offset-Based Pagination** (`LIMIT` and `OFFSET`) suffers from two major problems:

1.  **Performance Degradation**: `OFFSET X LIMIT Y` requires the database to scan and discard `X` records before returning `Y` records. For large tables, this becomes $O(N)$ and degrades rapidly.
2.  **Inconsistent Data (Drift)**: In real-time session tracking, sessions are constantly created or deleted. If a user deletes a session or creates a new one while paginating, items shift positions. This results in duplicate items shown on page changes or missed items entirely.

---

## Proposed Solution: Cursor-Based Pagination

We implemented **Cursor-Based Pagination** as the primary pagination strategy for all list and collection endpoints.

In this model, the client supplies a `cursor` (the unique ID of the last item returned on the current page) and a `limit`. The database filters directly using the cursor index and returns the next contiguous page.

### Key Benefits

1.  **Constant-Time Complexity ($O(1)$)**: Because the cursor uses the primary key index (`id`), the database executes an index-range scan directly to the cursor's location. This remains fast regardless of whether we are reading page 1 or page 10,000.
2.  **Mutation-Resilient (No Drift)**: The pagination is anchored to unique, immutable keys. If new records are inserted or deleted while a client is paging, the list is stable; items are never skipped or duplicated.
3.  **Concurrent Count & CORS Header Provisioning**: To satisfy the CORS metadata requirements, the paginator executes a concurrent database count query alongside the page slice fetch using `Promise.all`. This resolves the overall counts in parallel and populates the client-facing `X-Total-Count` and `X-Page-Count` HTTP response headers (defined in `exposedHeaders`) without adding serial round-trip latency.
4.  **Preserved Chronological Ordering**: We sort by `createdAt` descending as the primary order, and use `id` descending as the unique tie-breaker cursor:
    ```typescript
    orderBy: [{ createdAt: 'desc' }, { id: 'desc' }];
    ```
    This guarantees stable ordering while maintaining correct chronological behavior.

---

## Utility Architecture: `paginateWithCursor`

We created a generic, type-safe pagination utility in [pagination.ts](../../../src/core/common/utils/pagination.ts):

- **Default Parameters**: `limit = 100`, max `limit = 100`.
- **Decoupled Selection & Sorting**: It accepts a callback that fetches data from the database, allowing services to define custom `where` filters, relations, and select parameters while leaving pagination boundaries to the utility.

---

## Standardized JSON API Format

All paginated endpoints return metadata nested alongside results:

```json
{
  "success": true,
  "message": "Resource retrieved successfully",
  "data": {
    "records": [...],
    "pagination": {
      "cursor": "current_cursor_id_or_null",
      "nextCursor": "next_page_cursor_id_or_null",
      "hasMore": true,
      "limit": 100,
      "totalCount": 1250,
      "totalPages": 13
    }
  }
}
```
