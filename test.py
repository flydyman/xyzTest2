import unittest

from main import *


class TestUser(unittest.TestCase):

    def test_create(self):
        query = insert(user_table).values(
            username='unit_test',
            password=hash_pass('unit_test'),
            is_blocked=False
        )
        with db_engine.connect() as conn:
            res = conn.execute(query)
            conn.commit()
        user_id = res.lastrowid
        self.assertNotEqual(user_id, 0)

    def test_get_by_id(self):
        query = select(user_table).where(
            user_table.c.id == 1
        )
        with db_engine.connect() as conn:
            res = conn.execute(query)
        rows = [r for r in res]
        row = rows[0]
        username = row['username']
        self.assertEqual(username, 'test1')

    def test_get_by_name(self):
        query = select(user_table).where(
            user_table.c.username == 'test1'
        )
        with db_engine.connect() as conn:
            res = conn.execute(query)
        rows = [r for r in res]
        username = rows[0]['username']
        self.assertEqual(username, 'test1')

    def test_get_by_method(self):
        user = get_user('test1')
        self.assertEqual(user.username, 'test1')


class TestToken(unittest.TestCase):

    def test_create(self):
        data = {"sub": 'unit_test'}
        res = create_access_token(data)
        payload = jwt.decode(res, SECRET_KEY, algorithms=[ALGORITHM])
        name = payload.get("sub")
        self.assertEqual(name, 'unit_test')


class TestCipher(unittest.TestCase):
    source = "Simple string just for 1 test"
    target = "Y1hfQ1hQFkRMSwgMBEQPExQcSQwEHk1fTwQUAQc="

    def test_encode(self):
        res = xor_cipher(self.source)
        self.assertEqual(res.decode(), self.target)

    def test_decode(self):
        res = xor_cipher(self.target, False)
        self.assertEqual(res, self.source)

if __name__ == '__main__':
    unittest.main()
