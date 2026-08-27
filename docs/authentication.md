# Authentication

## Sign-in

The page is a map of what is exploitable across an estate, which team owns it, and what
has not been patched. "Only reachable on the internal network" is not the same as "fine to
leave open", and the shared token below is authentication without identity: everybody who
holds it is the same person, and nothing anyone does can be attributed.

So there are two mechanisms, and they coexist. A person signs in. A script presents a
token, because a script cannot complete an interactive redirect and should not be asked to.

### OpenID Connect

Plain OIDC, so Entra, Okta, Keycloak and Dex are the same configuration. Set an issuer and
sign-in is on:

```sh
export PATCHWRIGHT_OIDC_CLIENT_SECRET=…      # from the app registration
export PATCHWRIGHT_SESSION_KEY=…             # openssl rand -base64 32

patchwright serve \
  --oidc-issuer https://login.microsoftonline.com/<tenant-id>/v2.0 \
  --oidc-client-id <application-id> \
  --oidc-redirect-url https://patchwright.example.com/auth/callback \
  --oidc-allowed-group <group-object-id>
```

Or in the chart. The secrets are **referenced**, never inlined: a client secret in values
is readable by anyone who can read the HelmRelease, and lands in git the moment those
values are committed. Each is a name/key pair because the key names belong to whatever
secret store produced them, not to this chart:

```yaml
auth:
  oidc:
    issuer: https://login.microsoftonline.com/<tenant-id>/v2.0
    clientID: <application-id>
    redirectURL: https://patchwright.example.com/auth/callback
    allowedGroups: [<group-object-id>]
    clientSecretRef:
      name: patchwright-app-registration-client   # e.g. akv2k8s output
      key: clientSecret
    sessionKeyRef:
      name: patchwright-session
      key: sessionKey
```

They can equally be keys in `credentialsSecretName`, named exactly
`PATCHWRIGHT_OIDC_CLIENT_SECRET` and `PATCHWRIGHT_SESSION_KEY`, if that suits better than
a reference.

Three endpoints appear: `/auth/login`, `/auth/callback`, `/auth/logout`. They exist only
when an issuer is configured, so nobody finds a sign-in that cannot work.

### Registering the application

With Entra, on an app registration:

- a **web** redirect URI exactly matching `--oidc-redirect-url`
- a **client secret**, which becomes `PATCHWRIGHT_OIDC_CLIENT_SECRET`
- optionally a **groups claim** on the token configuration, if `allowedGroups` is used —
  Entra omits groups unless asked, and see below for what happens then

`https://login.microsoftonline.com/<tenant-id>/v2.0` is the issuer. The v2.0 suffix
matters: the v1 endpoint advertises different metadata and its tokens will not verify.

### Who gets in

`allowedGroups`, `allowedEmails` and `allowedDomains` all apply, and **every configured
restriction has to pass** — a guest account in the right group still fails a domain
restriction. Leave them all empty only when the provider itself is the boundary, and the
service says so at startup rather than leaving it implicit.

**A configured restriction that cannot be evaluated refuses everybody.** If `allowedGroups`
is set and the provider sends no groups claim, nobody is admitted. That is deliberate: the
alternative is admitting everyone because a claim was missing, which satisfies the
configuration file while defeating its purpose, and does so silently. A refused sign-in is
logged with the identity and the reason.

### What a session is

A cookie holding a subject, a display name and an expiry, signed with `PATCHWRIGHT_SESSION_KEY`
(HMAC-SHA256), `HttpOnly`, `SameSite=Lax`, and `Secure` whenever the request arrived over
TLS — including via a proxy that terminated it, which is where it matters most.

Group membership is checked once at sign-in and **not** stored in the cookie, so a cookie
cannot be replayed to assert a group. The trade is that withdrawing someone's access takes
effect when their session expires rather than immediately, which is why the default
lifetime is twelve hours rather than weeks.

Without `PATCHWRIGHT_SESSION_KEY` a key is generated at startup. That is safe, and it signs
everybody out on every rollout and cannot work across replicas, so it warns.

### Machine clients

`PATCHWRIGHT_API_TOKEN` continues to work exactly as before, alongside sign-in. Either a
valid session or a valid token is sufficient; neither is required when the other is
present. An unauthenticated request gets a redirect if it looks like a browser navigation
and a `401` otherwise — redirecting a Backstage fetch into an HTML login page would turn a
clear failure into a confusing success.

The health probes and `/favicon.png` stay open, and `/metrics` unless
`server.metricsAuth` is set. A probe that needs a credential makes a pod fail its own
liveness check.

