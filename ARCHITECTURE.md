# Inner architecture of the manager

![architecture diagram](docs/img/manager_architecture_diagram.svg)

## API

The API server is implemented using [`aiohttp`](https://docs.aiohttp.org/en/stable/). This framework provides the application skeleton and manages application runtime. The manager is actually a normal web application with the slight difference that we don't save the data in a database but rather modify systems state.

## Data processing

From the web framework, we receive data as simple strings. After this step, we return a fully typed object with valid configuration (or an exception with an error).

### Parsing

We currently support YAML and JSON and decide based on `Content-Type` header (JSON being the default if no `Content-Type` header is provided). We use the Python's [build-in JSON parser](https://docs.python.org/3/library/json.html) and [`PyYAML`](https://pyyaml.org/).

### Schema and type validation

The parsing step returns a dict-like object, which does not provide any guarantees about it's content. We map the values from this object to a proper class object based on Python's native type annotations. The code to do this is custom made, no libraries needed.

### Normalization

After we move the configuration to the typed objects, we need to normalize its values for further use. For example, all `auto` values should be replaced by real infered values. The result of this step is yet another typed object, but different than the input one so that we can statically distinguish between normalized and not-normalized config data.

## Actual manager

The actual core of the whole application is originally named the manager. It keeps a high-level view of the systems state and performs all necessary operations to change the state to the desired one. It does not interact with the system directly, majority of interactions are hidden behing abstract backends.

Every other part of the processing pipeline is fully concurrent. The manager is a place where synchronization happens.

## Backends

The Knot Resolver Manager supports several backends, more specifically several service managers that can run our workers. The main one being `systemd` has several variants, so that it can run even without privileges. The other currently supported option is `supervisord`.

The used backend is chosen automatically on startup based on available privileges and other running software. This decision can be overriden manually using a command line option.

# Partial config updates

The pipeline described above works well when the user provides full configuration through the API. However, some users might want to make only partial changes as it allows several independent client applications to change different parts of the config independently without explicit synchronization on their part.

When a user submits a partial config, we parse it and change the last used config accordingly. The change happens before the normalization step as that is the first step modifing provided data.