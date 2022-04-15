from datetime import datetime, timedelta

import jwt
import pytest
from minumtium.infra.authentication import AuthenticationException
from minumtium.modules.idm import UserRepository, Session, MAX_LOGIN_TRIALS, LOGIN_COOLDOWN_MINUTES

from minumtium_simple_jwt_auth import SimpleJwtAuthentication


def test_validate_token(secret_key, auth_adapter):
    expiration_date = datetime.now() + timedelta(minutes=1)
    token = generate_jwt_token('valid', '0', expiration_date, secret_key)
    session = auth_adapter.validate_token(token)

    assert isinstance(session, Session)
    assert session.expiration_date == expiration_date
    assert session.user_id == '0'
    assert session.username == 'valid'


def test_validate_token_invalid_token(auth_adapter):
    with pytest.raises(AuthenticationException):
        auth_adapter.validate_token('invalid')


def test_validate_token_with_invalid_data_user_id(secret_key, auth_adapter):
    expiration_date = datetime.now() + timedelta(minutes=1)
    token = generate_jwt_token('valid', '1', expiration_date, secret_key)
    with pytest.raises(AuthenticationException):
        auth_adapter.validate_token(token)


def test_validate_token_with_invalid_data_user_name(secret_key, auth_adapter):
    expiration_date = datetime.now() + timedelta(minutes=1)
    token = generate_jwt_token('invalid', '0', expiration_date, secret_key)
    with pytest.raises(AuthenticationException):
        auth_adapter.validate_token(token)


def test_validate_token_expired_session(secret_key, auth_adapter):
    expiration_date = datetime.now() - timedelta(minutes=1)
    token = generate_jwt_token('invalid', '0', expiration_date, secret_key)
    with pytest.raises(AuthenticationException):
        auth_adapter.validate_token(token)


def test_authenticate(secret_key, auth_adapter):
    token = auth_adapter.authenticate('valid', 'valid')
    decoded_token = decode_jwt_token(token, secret_key)

    assert decoded_token['username'] == 'valid'
    assert decoded_token['userid'] == '0'

    parsed_date = datetime.strptime(
        decoded_token['expiration_date'], SimpleJwtAuthentication.SESSION_DURATION_FORMAT)
    assert datetime.now() + timedelta(hours=auth_adapter.session_duration) - \
        timedelta(minutes=1) < parsed_date


@pytest.mark.parametrize('username, password', [('valid', 'invalid'),
                                                ('invalid', 'valid')])
def test_authenticate_invalid_credentials(username, password, auth_adapter):
    with pytest.raises(AuthenticationException):
        auth_adapter.authenticate(username, password)


def test_authenticate_almost_all_max_trials_with_success(auth_adapter):
    auth_adapter.trials = {}
    for _ in range(MAX_LOGIN_TRIALS - 1):
        # noinspection PyBroadException
        try:
            auth_adapter.authenticate('valid', 'invalid')
        except:
            pass

    auth_adapter.authenticate('valid', 'valid')


def test_authenticate_max_trials_with_success(auth_adapter):
    auth_adapter.trials = {}
    for _ in range(MAX_LOGIN_TRIALS):
        # noinspection PyBroadException
        try:
            auth_adapter.authenticate('valid', 'valid')
        except:
            pass
    auth_adapter.authenticate('valid', 'valid')


def test_authenticate_max_trials_lock(auth_adapter):
    auth_adapter.trials = {}
    for _ in range(MAX_LOGIN_TRIALS):
        # noinspection PyBroadException
        try:
            auth_adapter.authenticate('valid', 'invalid')
        except:
            pass

    with pytest.raises(AuthenticationException):
        auth_adapter.authenticate('valid', 'valid')


def test_authenticate_after_trial_timeout(auth_adapter):
    auth_adapter.trials = {}
    for _ in range(MAX_LOGIN_TRIALS):
        # noinspection PyBroadException
        try:
            auth_adapter.authenticate('valid', 'invalid')
        except:
            pass

    with pytest.raises(AuthenticationException):
        auth_adapter.authenticate('valid', 'valid')

    auth_adapter.trials['valid']['timestamp'] = datetime.now() - \
        timedelta(minutes=LOGIN_COOLDOWN_MINUTES, seconds=1)
    assert not auth_adapter._is_max_trials_expired('valid')


def test_password_criteria(auth_adapter):
    assert auth_adapter.is_valid_password('Twelvechar1!')


@pytest.mark.parametrize('password', ['TwelveChars1',
                                      'twelveChars!!',
                                      'TwelveChars12',
                                      'twelvechars1!'])
def test_password_criteria_negatove(password, auth_adapter):
    assert not auth_adapter.is_valid_password(password)


def test_default_username_is_created(user_repository: UserRepository, auth_adapter):
    assert 'minumtium' in [user.username for user in user_repository.all()]


def generate_jwt_token(username: str, user_id: str, expiration: datetime, secret: str):
    return jwt.encode({
        'username': username,
        'userid': user_id,
        'expiration_date': expiration.strftime(SimpleJwtAuthentication.SESSION_DURATION_FORMAT)
    }, secret, algorithm=SimpleJwtAuthentication.ALGORITHM)


def decode_jwt_token(token: str, secret_key: str):
    return jwt.decode(token.encode('utf-8'), secret_key, algorithms=SimpleJwtAuthentication.ALGORITHM)


@pytest.fixture()
def secret_key():
    return 'abc123dummykey'


@pytest.fixture()
def user_repository(users_database_adapter):
    # noinspection PyTypeChecker
    return UserRepository(users_database_adapter)


@pytest.fixture()
def auth_adapter(secret_key, user_repository):
    return SimpleJwtAuthentication({'jwt_key': secret_key,
                                    'session_duration_hours': 6}, user_repository)
