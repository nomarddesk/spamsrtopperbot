"""Offline SQLite state tests (do not need Telegram token or package)."""
import ast
import os
import sqlite3
import tempfile
import time
from pathlib import Path

source = Path(__file__).with_name('bot.py').read_text()
tree = ast.parse(source)
cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'Store')
namespace = {
    'Path': Path, 'sqlite3': sqlite3, 'time': time, 'secrets': __import__('secrets'),
    'BURST_THRESHOLD': 200, 'BURST_WINDOW_SECONDS': 600,
}
exec(compile(ast.Module(body=[cls], type_ignores=[]), 'bot.py', 'exec'), namespace)
Store = namespace['Store']

with tempfile.TemporaryDirectory() as tmp:
    path = os.path.join(tmp, 'test.db')
    db = Store(path)
    burst_id = None
    t = time.time()
    for n in range(200):
        event, new_burst, count = db.record_join(1000 + n, 200000 + n, f'User {n}', None, t + n * .05)
        assert event is not None
        if n < 199:
            assert new_burst is None, (n,new_burst)
        else:
            burst_id = new_burst
            assert burst_id is not None and count == 200
    assert db.burst_stats(burst_id) == (200,200)
    db.keep(200000)
    assert db.is_kept(200000)
    assert db.burst_stats(burst_id) == (200,199)
    db.unkeep(200000)
    assert db.burst_stats(burst_id) == (200,200)
    db.set_user_decision(200001,'left')
    assert db.burst_stats(burst_id) == (200,199)
    db.record_join(5000, 300001, 'After burst', None, t+15)
    assert db.burst_stats(burst_id) == (201,200)
    token=db.arm_burst(burst_id)
    assert db.start_burst(burst_id,'incorrect') is False
    assert db.start_burst(burst_id,token) is True
    assert db.start_burst(burst_id,token) is False
    db.finish_burst(burst_id)
    db.close()
    db2=Store(path)
    assert db2.burst(burst_id)['state']=='done'
    assert db2.burst_stats(burst_id) == (201,200)
    db2.close()
print('PASS: 200-join alert, Keep protection, leave detection, burst extension, confirm tokens, persistence')
