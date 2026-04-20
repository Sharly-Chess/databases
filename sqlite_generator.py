import argparse
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path
from sqlite3 import Connection, connect

from aes_ecb import AesEcb


class SqliteGenerator(ABC):
    """An abstract SQLite generator class."""

    def __init__(
        self,
        description: str,
        default_output_filename: str,
    ):
        parser = argparse.ArgumentParser(description=description)
        parser.add_argument(
            '--output',
            type=Path,
            default=Path(default_output_filename),
            help='Path for the output SQLite encrypted file',
        )
        parser.add_argument(
            '-k',
            '--key',
            type=str,
            required=True,
            help='Key used for AES-CBC encryption',
        )
        args = parser.parse_args()
        self.output_file: Path = args.output.resolve()
        self.key: str = args.key

    @classmethod
    def _create_sqlite_database(
        cls,
        sqlite_file: Path,
    ) -> Connection:
        sqlite_file.unlink(missing_ok=True)
        sqlite_file.parent.mkdir(parents=True, exist_ok=True)
        return connect(database=sqlite_file, detect_types=1, uri=True)

    def run(self):
        with tempfile.TemporaryDirectory() as tmp:
            sqlite_file: Path = self.generate_sqlite_database(Path(tmp))
            AesEcb.encrypt_file(sqlite_file, self.output_file, self.key)
        print(f'SQLite database encrypted to {self.output_file}.')

    @abstractmethod
    def generate_sqlite_database(
        self,
        tmp_dir: Path,
    ):
        pass
