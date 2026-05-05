import sqlite3

DB_PATH = 'packets.db'

CREATE_TABLE = '''
    CREATE TABLE IF NOT EXISTS packets (
        time      TEXT,
        protocol  TEXT,
        src_addr  TEXT,
        dst_addr  TEXT,
        src_port  INTEGER,
        dst_port  INTEGER
    )
'''


class PacketDatabase:
    """Thin wrapper around the SQLite packet log."""

    def __init__(self, path=DB_PATH):
        self.conn = sqlite3.connect(path)
        self._cursor = self.conn.cursor()
        self._cursor.execute(CREATE_TABLE)

    def log(self, time, protocol, src_addr, dst_addr, src_port, dst_port):
        self._cursor.execute(
            'INSERT INTO packets VALUES (?,?,?,?,?,?)',
            (time, protocol, src_addr, dst_addr, src_port, dst_port),
        )
        self.conn.commit()

    def close(self):
        self.conn.close()
