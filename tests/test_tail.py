"""LogTail: reading only what is new, and never a half-written line."""

import json

from score import LogTail


def row(key, ts, text="hello there friend"):
    return {"ts": ts, "api_key": key, "input": text,
            "predicted_label": "POSITIVE", "confidence": 0.95}


def write(path, rows, mode="a", newline="\n"):
    with open(path, mode, encoding="utf-8", newline="") as fh:
        for r in rows:
            fh.write(json.dumps(r) + newline)


def test_first_poll_reads_everything_and_marks_every_client_dirty(tmp_path):
    log = tmp_path / "log.jsonl"
    write(log, [row("a", 1), row("b", 2), row("a", 3)], mode="w")
    tail = LogTail([str(log)])
    dirty, reset = tail.poll()
    assert dirty == {"a", "b"} and reset is False
    assert [r["ts"] for r in tail.by_key["a"]] == [1, 3]


def test_later_polls_return_only_clients_with_new_rows(tmp_path):
    log = tmp_path / "log.jsonl"
    write(log, [row("a", 1), row("b", 2)], mode="w")
    tail = LogTail([str(log)])
    tail.poll()
    assert tail.poll() == (set(), False)
    write(log, [row("b", 3)])
    dirty, _ = tail.poll()
    assert dirty == {"b"}
    assert len(tail.by_key["a"]) == 1 and len(tail.by_key["b"]) == 2


def test_a_half_written_line_waits_for_its_newline(tmp_path):
    log = tmp_path / "log.jsonl"
    write(log, [row("a", 1)], mode="w")
    tail = LogTail([str(log)])
    tail.poll()
    partial = json.dumps(row("a", 2))
    with open(log, "a", encoding="utf-8", newline="") as fh:
        fh.write(partial[:20])
    assert tail.poll()[0] == set()
    with open(log, "a", encoding="utf-8", newline="") as fh:
        fh.write(partial[20:] + "\n")
    dirty, _ = tail.poll()
    assert dirty == {"a"} and len(tail.by_key["a"]) == 2


def test_windows_style_crlf_lines_are_handled(tmp_path):
    log = tmp_path / "log.jsonl"
    write(log, [row("a", 1), row("a", 2)], mode="w", newline="\r\n")
    tail = LogTail([str(log)])
    tail.poll()
    write(log, [row("a", 3)], newline="\r\n")
    dirty, _ = tail.poll()
    assert dirty == {"a"} and len(tail.by_key["a"]) == 3


def test_rows_stay_in_time_order_even_if_they_arrive_late(tmp_path):
    log = tmp_path / "log.jsonl"
    write(log, [row("a", 5)], mode="w")
    tail = LogTail([str(log)])
    tail.poll()
    write(log, [row("a", 2), row("a", 9)])
    tail.poll()
    assert [r["ts"] for r in tail.by_key["a"]] == [2, 5, 9]


def test_corrupt_and_incomplete_rows_are_skipped(tmp_path):
    log = tmp_path / "log.jsonl"
    with open(log, "w", encoding="utf-8", newline="") as fh:
        fh.write("not json at all\n")
        fh.write(json.dumps({"ts": 1, "api_key": "a"}) + "\n")
        fh.write(json.dumps(row("a", 3)) + "\n")
        fh.write("\n")
    tail = LogTail([str(log)])
    dirty, _ = tail.poll()
    assert dirty == {"a"} and len(tail.by_key["a"]) == 1


def test_a_shrunken_file_resets_and_rereads_from_the_start(tmp_path):
    log = tmp_path / "log.jsonl"
    write(log, [row("a", 1), row("a", 2), row("b", 3)], mode="w")
    tail = LogTail([str(log)])
    tail.poll()
    write(log, [row("c", 10)], mode="w")
    dirty, reset = tail.poll()
    assert reset is True and dirty == {"c"}
    assert set(tail.by_key) == {"c"}


def test_missing_file_is_fine_until_it_appears(tmp_path):
    log = tmp_path / "later.jsonl"
    tail = LogTail([str(log)])
    assert tail.poll() == (set(), False)
    write(log, [row("a", 1)], mode="w")
    assert tail.poll()[0] == {"a"}


def test_two_logs_are_merged_by_client(tmp_path):
    one, two = tmp_path / "1.jsonl", tmp_path / "2.jsonl"
    write(one, [row("a", 1)], mode="w")
    write(two, [row("a", 2), row("b", 3)], mode="w")
    tail = LogTail([str(one), str(two)])
    dirty, _ = tail.poll()
    assert dirty == {"a", "b"} and len(tail.by_key["a"]) == 2
