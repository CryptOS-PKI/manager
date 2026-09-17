# Deploying the Fleet Manager standalone (systemd, no Kubernetes)

The README documents Kubernetes and `docker compose`. This covers a third case
that turns out to be the common one for a small fleet: **a single Linux host,
systemd, local Postgres, no container runtime**. It also records the traps found
doing it for real, several of which are not obvious from the other docs.

Throughout, the placeholder organisation is **ACME** (`acme.example`). Replace
it with your own.

## 0. Before you start: there may be no image to pull

The README's `docker run ghcr.io/cryptos-pki/manager:vX.Y.Z` and
`helm install ... oci://ghcr.io/cryptos-pki/charts/fleet-manager` both require a
**published release**. Releases are cut by hand (see *Releasing*), and the image
and chart are built by the tag. Until the first tag exists, neither path
resolves and you must build from source:

```sh
git clone --depth 1 https://github.com/CryptOS-PKI/manager.git
cd manager
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags="-s -w" -o cryptos-fleet-manager ./cmd/manager
```

The `web` bundle is embedded via `go:embed`, so this single static binary is the
whole application — no separate frontend build, no Node toolchain on the target
host. Build on a workstation and copy the binary; the target needs nothing but
glibc-free Linux and Postgres.

## 1. `--trust` is NOT your fleet CA chain

**This is the single easiest mistake to make.** A CryptOS node presents an
**ephemeral self-signed server certificate** whose subject is the node's own
address (`CN=10.0.0.20`), *not* a certificate issued by the CA that node
operates. Passing your fleet's CA chain to `cryptosctl --trust` therefore fails:

```console
$ cryptosctl --endpoint 10.0.0.20:443 --trust acme-ca-chain.pem status
cryptosctl: rpc error: code = Unavailable desc = connection error:
  desc = "transport: authentication handshake failed: tls: failed to verify
  certificate: x509: certificate signed by unknown authority"
```

The error reads like a broken chain. It is not — it is the wrong *kind* of
anchor. The node relies on **client**-auth for its security; server identity is
deliberately weak. Capture the node's own presented certificate and use that:

```sh
openssl s_client -connect 10.0.0.20:443 -showcerts </dev/null 2>/dev/null \
  | openssl x509 -outform pem > node-10.0.0.20.pem

cryptosctl --endpoint 10.0.0.20:443 \
  --identity admin.crt --identity-key admin.key \
  --trust node-10.0.0.20.pem status
```

Two distinct things are easy to conflate:

| Setting | What it is |
| --- | --- |
| `cryptosctl --trust` | the **node's self-signed server cert** (TLS anchor) |
| manager `nodes[].caCertPath` | the node's **CA identity chain** — root = 1 cert, intermediate = 2 certs `[intermediate, root]` |

They are different files and are not interchangeable.

## 2. There is no `config get` — `apply` can silently drop your profiles

`cryptosctl config` exposes only `apply`:

```console
$ cryptosctl config --help
Available Commands:
  apply       Apply a machine configuration
```

There is **no way to read a node's current `machine.yaml` back off the node**,
and `apply` takes a *complete* configuration. So if you applied a profile at
some point (say a server profile for one host) and later apply a config built
from your original file, that profile is **silently removed** — no warning, and
`ca list-issued` is the only way you'd notice.

Keep the authoritative `machine.yaml` in version control and treat it as the
only source of truth. Never hand-build an `apply` payload from memory.

> Related: profiles are also not readable via any `config`/`ca` verb, because
> the hot-apply normaliser zeroes the `Profiles` field. `ca list-issued` is the
> only evidence a profile took effect.

## 3. The operator CA does not have to be a CryptOS node

[`operator-pki.md`](operator-pki.md) walks through provisioning a **dedicated
CryptOS node** as the operator CA, then a three-command CSR ferry to chain it
under the fleet root. That is the dogfooding path and it is correct, but it
assumes you have a spare node.

For a two-node fleet (one root, one intermediate) there is no third node, and
standing one up means a new machine plus a subordinate ceremony. You usually
don't need it: **`operatorCAPath` is just the client-auth trust anchor.** The
manager accepts any certificate issued by that CA at the handshake and then
reads the level extension to decide privilege. Nothing requires the operator CA
to be CryptOS-issued.

A plain OpenSSL operator CA is sufficient, and it has a real advantage: it needs
**no `config apply` against a production CA node at all**.

```sh
# Operator CA — 10y, may issue leaves but no further sub-CAs.
openssl ecparam -name secp384r1 -genkey -noout -out operator-ca.key
chmod 600 operator-ca.key
openssl req -x509 -new -key operator-ca.key -sha384 -days 3650 \
  -subj "/C=US/O=ACME/CN=ACME Operator CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out operator-ca.crt
```

**Trade-off to understand before choosing this:** every certificate your fleet
CA issues that carries `clientAuth` EKU would *also* satisfy a handshake if you
instead pointed `operatorCAPath` at the fleet intermediate. Use a **separate**
operator CA (as above) rather than reusing the fleet intermediate, so the set of
certs that can open a TLS session to the management plane stays exactly the set
you minted for operators.

### The level extension in OpenSSL form

`operator-pki.md` gives the level extension only as a YAML byte sequence for a
cryptos profile (`value: [19, 5, 97, 100, 109, 105, 110]`). When your operator
CA is OpenSSL, you need the same DER in `-extfile` form. These are identical
bytes — `0x13` is ASN.1 `PrintableString`, `0x05` its length:

```ini
# op-admin.ext
extendedKeyUsage = clientAuth
keyUsage = critical, digitalSignature
1.3.6.1.4.1.59999.1.1 = DER:13:05:61:64:6D:69:6E
```

| Level | DER | `opext` bytes |
| --- | --- | --- |
| `viewer` | `DER:13:06:76:69:65:77:65:72` | `[19, 6, 118, 105, 101, 119, 101, 114]` |
| `operator` | `DER:13:08:6F:70:65:72:61:74:6F:72` | `[19, 8, 111, 112, 101, 114, 97, 116, 111, 114]` |
| `admin` | `DER:13:05:61:64:6D:69:6E` | `[19, 5, 97, 100, 109, 105, 110]` |

Mint and verify an operator certificate:

```sh
openssl ecparam -name secp384r1 -genkey -noout -out operator-admin.key
chmod 600 operator-admin.key
openssl req -new -key operator-admin.key -subj "/CN=you@acme.example" -out operator-admin.csr
openssl x509 -req -in operator-admin.csr -CA operator-ca.crt -CAkey operator-ca.key \
  -CAcreateserial -days 365 -sha384 -extfile op-admin.ext -out operator-admin.crt

openssl x509 -in operator-admin.crt -text -noout | grep -A2 '59999.1.1'   # ..admin
openssl verify -CAfile operator-ca.crt operator-admin.crt                 # OK

openssl pkcs12 -export -inkey operator-admin.key -in operator-admin.crt \
  -certfile operator-ca.crt -name "ACME operator (admin)" -out operator-admin.p12
```

Import the `.p12` into your OS/browser keystore; the browser offers it during
the manager's handshake.

## 4. Config key casing is not uniform

Most keys are camelCase, but two are snake_case. A camelCase spelling of either
is not an error — it is silently ignored, which reads as "the feature doesn't
work":

| snake_case (required) | Not `database_url` → `databaseUrl` |
| --- | --- |
| `database_url` | selects the Postgres store |
| `operator_ca_node` | enables operator-cert revocation checking |

Everything else — `listen`, `corsOrigins`, `authBypass`, `tlsCert`, `tlsKey`,
`operatorCAPath`, `nodes[].adminCertPath`, `nodes[].adminKeyPath`,
`nodes[].caCertPath` — is camelCase.

If `operator_ca_node` is unset the manager starts and logs:

```
manager: no operator_ca_node configured, operator-cert revocation not enforced
```

That is a real gap, not a cosmetic warning: a revoked operator certificate keeps
working until you set it.

## 5. A worked `config.yaml`

```yaml
listen: "0.0.0.0:443"

authBypass: false
tlsCert: "/etc/ssl/certs/fm.acme.example.fullchain.pem"
tlsKey: "/etc/ssl/private/fm.acme.example.key"
operatorCAPath: "/etc/cryptos/fleet/operator-ca.crt"

database_url: "postgres://manager:CHANGEME@127.0.0.1:5432/manager"

nodes:
  - name: pki-root
    endpoint: "10.0.0.20:443"
    role: root
    adminCertPath: "/etc/cryptos/fleet/pki-root/admin.crt"
    adminKeyPath: "/etc/cryptos/fleet/pki-root/admin.key"
    caCertPath: "/etc/cryptos/fleet/pki-root/ca.pem"      # 1 cert
  - name: pki-inter
    endpoint: "10.0.0.21:443"
    role: intermediate
    adminCertPath: "/etc/cryptos/fleet/pki-inter/admin.crt"
    adminKeyPath: "/etc/cryptos/fleet/pki-inter/admin.key"
    caCertPath: "/etc/cryptos/fleet/pki-inter/ca.pem"     # 2 certs [inter, root]
```

Database setup — the manager runs its own idempotent migrator and seeds the
catalog on first start, so an empty database is all you need:

```sh
sudo -u postgres psql -c "CREATE ROLE manager LOGIN PASSWORD 'CHANGEME';"
sudo -u postgres psql -c "CREATE DATABASE manager OWNER manager;"
```

Node `adminCertPath`/`adminKeyPath` are **not** required for the process to
start — the manager parses the node list and dials lazily, logging
`manager: N node(s) configured`. You can bring the UI up first and add node
credentials after.

### ⚠ The manager host holds a CA-admin client key

`adminKeyPath` is the private key of a credential that can drive your CA nodes'
management API. Putting the Fleet Manager on a host means **that host now holds
CA-admin authority**. This is inherent to the design — the FM is the thing that
operates the fleet — but treat the FM host as a tier-0 asset accordingly:
`0600 root`, full-disk encryption, and the same access controls as the CA nodes
themselves. The FM's *own* peer certificate deliberately lacks `keyCertSign`
and `cRLSign`, so the FM cannot sign certificates; the admin client key is a
separate and more powerful thing.

## 6. systemd unit

The manager binds 443, which is privileged. Grant the one capability rather
than running as root:

```ini
[Unit]
Description=CryptOS Fleet Manager
After=network-online.target postgresql.service
Wants=network-online.target
Requires=postgresql.service

[Service]
ExecStart=/usr/local/bin/cryptos-fleet-manager -config /etc/cryptos/fleet/config.yaml
Restart=on-failure
RestartSec=5s

User=fleetmgr
Group=fleetmgr
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictSUIDSGID=true
ReadOnlyPaths=/etc/cryptos/fleet /etc/ssl/certs /etc/ssl/private

[Install]
WantedBy=multi-user.target
```

The binary takes exactly one flag:

```console
$ cryptos-fleet-manager --help
Usage of /usr/local/bin/cryptos-fleet-manager:
  -config string
        path to the manager's YAML config file (default "config.yaml")
```

### Debian/Ubuntu: `/etc/ssl/private` will deny you

On Debian-family hosts `/etc/ssl/private` is `0710 root:ssl-cert`. A service
user that is not in `ssl-cert` **cannot traverse the directory**, so the key is
unreadable no matter what mode the key file itself has. The failure is:

```
manager: tls: load server cert: open /etc/ssl/private/fm.acme.example.key: permission denied
```

Note the manager gets as far as `using postgres store` and
`N node(s) configured` before this — Postgres and the node list are fine; only
TLS failed. Fix with the conventional group rather than loosening the
directory:

```sh
sudo usermod -aG ssl-cert fleetmgr
sudo chown root:ssl-cert /etc/ssl/private/fm.acme.example.key
sudo chmod 640 /etc/ssl/private/fm.acme.example.key
```

## 7. Verify without a browser

Prove the mTLS listener end to end before fighting keystore imports:

```sh
# Expect HTTP 200 and the SPA.
curl -sS --cert operator-admin.crt --key operator-admin.key \
  --cacert acme-ca-chain.pem https://fm.acme.example/ -o /dev/null -w '%{http_code}\n'

# Negative control — no client cert must be REFUSED, not served.
curl -sS --cacert acme-ca-chain.pem https://fm.acme.example/ -o /dev/null -w '%{http_code}\n'
```

If the second command succeeds you have `authBypass: true` somewhere, and your
management plane is open to anyone who can reach the port.

## 8. Serving CA certificates and CRLs — use plain HTTP

A distribution point for your root/intermediate certificates and CRLs (for
domain-join trust rollout, AIA, and CDP) must be served over **`http://`, not
`https://`**. AIA and CDP URLs are fetched by clients that are in the middle of
*building* the trust path, so serving them over TLS that depends on that same
chain is a bootstrap loop. RFC 5280 expects HTTP here.

This means it does not contend with the manager on 443 — run a static file
server on 80 alongside it, serving only the public certificate and CRL files.
Never expose private keys from that directory.

## Related

- [`operator-pki.md`](operator-pki.md) — the dogfooded operator-CA-on-a-node path.
- ⚠ The level extension arc `1.3.6.1.4.1.59999.1.1` is a **placeholder**; an
  IANA Private Enterprise Number must replace it before GA, and the value has
  to change in lockstep in the cryptos profile config and
  `internal/authz/level.go`.
