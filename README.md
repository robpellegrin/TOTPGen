# TOTPGen

A lightweight Python application designed to generate Time-based One-Time Passwords (TOTP) in an offline environment.

# TODO

    - CLI Args:
        - add
            * Add an existing TOTP secret to storage.
            * Options: --name, --issuer, --secret, --digits, --algorithm, --period.
        - list
            * Show stored entries (name, issuer, last-used time, maybe masked secret).
            * Options: --verbose (show full data), --json, --csv.
        - show
            * Display current TOTP codes for one or more entries.
            * Options: --name (or --all), --format (padding/spacing), --qr (display qr code).
        - get
            * Print code for scripting (non-interactive, no extra output).
            * --name, --ttl (seconds remaining).
        - remove
            * Delete an entry.
            * Options: --name, --confirm/--yes.
        - rename
            * Rename an entry or change its label/issuer.
            * Options: --name, --new-name, --issuer.
        - export
            * Export one or more entries (encrypted or plain) for backup.
            * Options: --file, --format=(json, csv), --encrypt (prompt for passphrase).
        - import
            * Import entries from file or clipboard
            * Options: --file, --format, --merge/--replace.
        - audit
            * Show usage history or detect duplicate/weak secrets.
            * Options: --duplicates, --weak-check, --usage.

    - UI:
        - Plain print to stdout.
        - Optional QT interface (show --gui).
        - Optional TUI interface with curses (show --tui).
