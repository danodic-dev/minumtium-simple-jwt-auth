from typing import List, Dict

import pytest
from minumtium.infra.database import DataNotFoundException


@pytest.fixture()
def users_database_data() -> List:
    return [{'id': '0',
             'username': 'valid',
             'encrypted_password': '$2b$14$WPJmYmygdinbCJ3V4.N/c.X8llM3aTYlKs5gKFIalKq0rK7B1.R.i'},
            {'id': '1',
             'username': 'another_valid',
             'encrypted_password': '$2b$14$WPJmYmygdinbCJ3V4.N/c.X8llM3aTYlKs5gKFIalKq0rK7B1.R.i'}]


@pytest.fixture()
def users_database_adapter(users_database_data):
    class MockAdapter:
        def __init__(self, data: Dict):
            self.data = data

        def all(self):
            return self.data

        def find_by_id(self, id: str) -> Dict:
            return self.find_by_criteria({'id': id})[0]

        def find_by_criteria(self, criteria: Dict) -> List[Dict]:
            for user in self.data:
                for field, value in criteria.items():
                    if user[field] != value:
                        break
                else:
                    return [user]
            raise DataNotFoundException()

        def insert(self, data: Dict) -> str:
            if data['username'] == 'minumtium':
                self.data.append({'id': '2',
                                  'username': 'minumtium',
                                  'encrypted_password': '$2b$14$WPJmYmygdinbCJ3V4.N/c.X8llM3aTYlKs5gKFIalKq0rK7B1.R.i'})
                return '2'
            return '0'

        def delete(self, id: str):
            for user in self.data:
                if user['id'] == id:
                    break
            else:
                raise DataNotFoundException()

    # noinspection PyTypeChecker
    return MockAdapter(users_database_data)
