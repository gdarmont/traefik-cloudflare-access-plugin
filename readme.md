# Traefik Cloudflare Access Plugin
This plugins allows [Traefik](https://github.com/traefik/traefik) to validate request coming from your Cloudflare Zero Trust account.

## Configuration

### Static

```yaml
experimental:
  plugins:
    cloudflareaccess:
      moduleName: "github.com/gdarmont/traefik-cloudflare-access-plugin"
      version: "v0.1.0"
```

### Dynamic

The examples values here are extracted from [Golang example](https://developers.cloudflare.com/cloudflare-one/identity/authorization-cookie/validating-json/#golang-example)

```yaml
http:
  middlewares:
    cloudflare-access-test:
      cloudflareaccess:
        teamName: "test"
        clientID: "4714c1358e65fe4b408ad6d432a5f878f08194bdb4752441fd56faefa9b2b6f2"
        skipClientIDCheck: false
```
