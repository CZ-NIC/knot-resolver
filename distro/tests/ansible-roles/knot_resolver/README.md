# Knot Resolver

**WARNING**: Work in progress!

Role which sets up Knot Resolver and performs checks it is running, including:

- Setting up upstream repositories **and their signing key as trusted**
- Installing Knot Resolver
- Performs basic tests
- Configures DoH
- Tests DoH

## Supported Distributions

- Ubuntu

## Variables

- ``obs_repos``: list of used ``home:CZ-NIC:*`` OBS repositories, leave the
  default unless testing development builds
