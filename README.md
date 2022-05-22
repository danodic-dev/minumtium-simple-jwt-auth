# Minumtium Simple JWT Auth

A very simple JWT Auth adapter for the [minumtium](https://github.com/danodic-dev/minumtium) library.

### What can I use it for?

It is used to provide JWT token authentication using the [minumtium](https://github.com/danodic-dev/minumtium) library.

## Usage

Install it using your favorite package manager:

```commandline
pip install minumtium-simple-jwt-auth
```

```commandline
pipenv install minumtium-simple-jwt-auth
```

```commandline
poetry install minumtium-simple-jwt-auth
```

Then, provide it to your minumtium Idm service:

```python
from minumtium.modules.idm import IdmService, UserRepository
from minumtium_sql_alchemy_adapter import SqlAlchemyAdapter
from minumtium_simple_jwt_auth import MinumtiumSimpleJwtAuthentication

db_adapter = SqlAlchemyAdapter({'engine': 'sqlite_memory'}, 'posts')
auth_adapter = MinumtiumSimpleJwtAuthentication(configuration={
    'jwt_key': 'not a reliable key, change that quickly',
    'session_duration_hours': 1})

users_repository = UserRepository(db_adapter)
idm_service = IdmService(auth_adapter, users_repository)

idm_service.authenticate('jao', 'batata')
```