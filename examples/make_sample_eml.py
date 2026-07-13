from __future__ import annotations

import argparse
from email.message import EmailMessage
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a harmless sample EML for Threadsaw testing")
    parser.add_argument("output", nargs="?", type=Path, default=Path("sample.eml"))
    args = parser.parse_args()

    out = args.output.expanduser()
    out.parent.mkdir(parents=True, exist_ok=True)
    message = EmailMessage()
    message["From"] = "Vendor Billing <billing@example.test>"
    message["To"] = "Analyst <analyst@example.org>"
    message["Date"] = "Fri, 10 Jul 2026 12:30:00 -0400"
    message["Message-ID"] = "<threadsaw-demo@example.test>"
    message["Subject"] = "Updated bank details"
    message.set_content("Please review https://example.test/payment")
    message.add_alternative(
        '<p>Open <a href="https://external.example/login">the secure document</a>.</p>',
        subtype="html",
    )
    message.add_attachment(
        b"demo attachment",
        maintype="application",
        subtype="octet-stream",
        filename="invoice.dat",
    )
    out.write_bytes(message.as_bytes())
    print(out.resolve())


if __name__ == "__main__":
    main()
