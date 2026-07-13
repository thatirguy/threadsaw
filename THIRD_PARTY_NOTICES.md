# Third-party notices

Threadsaw source code is distributed under the MIT License in `LICENSE`. The complete application may also use or bundle the following third-party components, each under its own license or terms:

- **Public Suffix List** — vendored as `src/threadsaw/data/public_suffix_list.dat`; the file contains its Mozilla Public License 2.0 notice and snapshot metadata. Source project: publicsuffix.org.
- **OpenCV / opencv-python-headless** — used for offline QR decoding.
- **pypdfium2 / PDFium** — used to render bounded PDF pages for offline QR decoding. pypdfium2 and PDFium are distributed under permissive terms, with additional third-party notices shipped by the dependency.
- **libpst / readpst** — the only allowlisted external process, used for PST extraction.
- **extract-msg** — optional MSG parsing dependency.
- **Python and its standard library** — subject to the Python Software Foundation License.

Review the applicable licenses before redistributing a container, installer, or dependency bundle. Threadsaw does not download or update the Public Suffix List at runtime.

## Distribution note for MSG support

`extract-msg==0.55.0` is GPL-licensed. It is not installed by the default Threadsaw 1.3.0 container build. It remains available as the optional `msg` extra and through `THREADSAW_INSTALL_MSG=1`. Distributors enabling it must preserve its license and comply with applicable GPL obligations. The final built image should be scanned to capture its full transitive dependency and license set.
