# cloudify-cfy-docker

This repository contains `Dockerfile`s for certain Docker images that facilitate working with
Cloudify (such as images for CI/CD platforms).

To create an image, navigate to the directory containing the `Dockerfile` of choice and execute:
 
```bash
docker build --tag <name>:<version> .
```

For example:

```bash
docker build --tag cfyci:latest .
```

# Implementation Notes

## Character Encoding

All JSON/YAML files being read by the `cfyci` utility are assumed to be encoded with `UTF-8`.

## SSL Certificate Verification

If the `CLOUDIFY_SSL_TRUST_ALL` environment variable is defined, then we turn off
all warnings issued by third-party libraries during runtime (for example, by the
`requests` package). The underlying assumption here is that by specifying
`CLOUDIFY_SSL_TRUST_ALL`, the user also states that they know what they're doing.
