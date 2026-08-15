# Examples

| Example | What it shows |
| --- | --- |
| [`chat/`](./chat) | Interactive terminal chat: identity creation, seed discovery, BChat-protocol send, signed polling receive, on-disk cursor persistence. |
| [`api/`](./api) | HTTP service wrapping the SDK — `POST /messages` to send, `GET /messages` to receive. For driving BChat from a non-Node app. |

```bash
npm run example:chat
npm run example:api
```

Both mint a 25-word identity on first run and speak the real BChat wire
protocol, so they interoperate with the official clients.

Examples import the SDK from `../../src` so they stay in sync with the source
and are covered by `npm run typecheck` and `npm run lint`. They run against the
**live** BChat network.
