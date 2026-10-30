import uuid
from concurrent.futures import ThreadPoolExecutor

from superbrain.core.ids import IdGenerator, id_timestamp_ms, new_id


def test_ids_are_v7_and_strictly_increasing_across_4096_in_one_ms() -> None:
    gen = IdGenerator(now_ms=lambda: 1_700_000_000_000, random_bits=lambda n: 0)
    ids = [gen.next() for _ in range(5000)]
    assert ids == sorted(ids) and len(set(ids)) == 5000
    assert all(uuid.UUID(i).version == 7 and uuid.UUID(i).variant == uuid.RFC_4122 for i in ids)


def test_clock_rollback_keeps_ids_increasing() -> None:  # Review Focus 5
    times = iter([1000, 1000, 400, 400, 1001])
    gen = IdGenerator(now_ms=lambda: next(times), random_bits=lambda n: 0)
    ids = [gen.next() for _ in range(5)]
    assert ids == sorted(ids) and len(set(ids)) == 5


def test_ids_from_threads_are_unique() -> None:
    with ThreadPoolExecutor(8) as pool:
        ids = list(pool.map(lambda _: new_id(), range(8000)))
    assert len(set(ids)) == 8000


def test_id_timestamp_ms_reads_the_embedded_timestamp() -> None:
    gen = IdGenerator(now_ms=lambda: 1_700_000_000_123, random_bits=lambda n: 5)
    assert id_timestamp_ms(gen.next()) == 1_700_000_000_123


def test_counter_overflow_borrows_a_millisecond() -> None:
    gen = IdGenerator(now_ms=lambda: 1_700_000_000_000, random_bits=lambda n: 0)
    stamps = [id_timestamp_ms(gen.next()) for _ in range(4097)]
    assert stamps[4095] == 1_700_000_000_000 and stamps[4096] == 1_700_000_000_001
