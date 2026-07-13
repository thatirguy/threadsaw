from __future__ import annotations

from email.message import EmailMessage
from pathlib import Path

from threadsaw.case import initialize_case
from threadsaw.db import connect_db
from threadsaw.evaluate_email import evaluate_phishing_email
from threadsaw.ingest import ingest_path
from threadsaw.reports import write_timestamped_reports


def _write(path: Path) -> None:
    msg = EmailMessage()
    msg['From'] = 'sender@example.com'
    msg['To'] = 'recipient@example.com'
    msg['Date'] = 'Sat, 11 Jul 2026 12:00:00 +0000'
    msg['Message-ID'] = '<one@example.com>'
    msg['Subject'] = 'Urgent wire update'
    msg.set_content('Please send the wire urgently.')
    path.write_bytes(msg.as_bytes())


def test_large_case_report_writes_jsonl(tmp_path):
    evidence = tmp_path / 'evidence'; evidence.mkdir()
    case = tmp_path / 'case'; initialize_case(case)
    _write(evidence / 'one.eml')
    ingest_path(evidence, case, progress=lambda _m: None)
    conn = connect_db(case)
    try:
        ids = [r['message_sha256'] for r in conn.execute('SELECT message_sha256 FROM messages')]
        result = write_timestamped_reports(conn, case / 'reports' / 'core', ids, large_case=True)
    finally:
        conn.close()
    assert Path(result['messages_jsonl']).is_file()
    assert not (Path(result['output_directory']) / 'messages.json').exists()


def test_evaluate_email_writes_friendly_hit_report(tmp_path):
    evidence = tmp_path / 'evidence'; evidence.mkdir()
    case = tmp_path / 'case'; initialize_case(case)
    _write(evidence / 'one.eml')
    ingest_path(evidence, case, progress=lambda _m: None)
    conn = connect_db(case)
    try:
        sha = conn.execute('SELECT message_sha256 FROM messages').fetchone()[0]
        result = evaluate_phishing_email(conn, case, message_sha256=sha, email_path=None,
            allow_case_history_override=False, output_root=case / 'reports' / 'evaluate')
    finally:
        conn.close()
    text = Path(result['friendly_report']).read_text(encoding='utf-8')
    assert 'FACTORS THAT HIT' in text
    assert 'Why it hit:' in text
    assert sha in text
