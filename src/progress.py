from math import floor
from time import time


class Progress:
    """A utility class to display the progress of operations."""

    def __init__(
        self,
        total_count: int,
        delay: int = 10,
    ):
        self.total_count = total_count
        self.delay: int = delay
        assert self.delay > 0
        self.start_time: float = time()
        self.last_message_time: float = self.start_time
        self.last_message_count: int = 0

    def log(
        self,
        count: int,
    ):
        if not self.total_count:
            return
        now: float = time()
        if now - self.last_message_time < self.delay:
            return
        remaining_count: int = self.total_count - count
        items_per_second: float = (
            (count - self.last_message_count) / (now - self.last_message_time)
            + count / (now - self.start_time)
        ) / 2
        eta: int = floor(remaining_count / items_per_second)
        print(f'{floor(count / self.total_count * 100):02d}% ETA: {eta // 60:02d}:{eta % 60:02d}')
        self.last_message_count = count
        self.last_message_time = now


