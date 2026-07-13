# Threadsaw V2 prototype 0.3.3 release notes

Version 0.3.3 improves launcher usability on smaller displays and clarifies attachment actions.

## GUI changes

- Every notebook page now has a vertical scrollbar and mouse-wheel support when its content exceeds the available height. This is especially useful on the Phish Hunt page as the factor list grows.
- Notebook tabs use a larger bold font and additional padding so Workflow, Full Pipeline, Ingest Data, and the other module pages are visually distinct from ordinary labels.
- The attachment-copy checkbox has been removed.
- The Export Attachments page now has two explicit actions:
  - **Generate Attachment Report Only**
  - **Generate Report and Export Attachment Files**
- The command preview follows the attachment button being hovered or focused, so it clearly shows whether `--copy-files` and `--copy-output` will be used.

No case database migration or evidence re-ingestion is required.
