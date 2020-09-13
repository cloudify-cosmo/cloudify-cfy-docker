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
