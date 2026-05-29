# WebDAV — Tuta Drive

The proxy exposes a WebDAV server on port `5234` that gives you access to your Tuta Drive
file storage. You can mount it as a network drive, use it with rclone, or browse it in a
file manager.

## Mounting with davfs2 (Linux)

```bash
# Install davfs2:
sudo apt install davfs2   # Debian/Ubuntu
sudo dnf install davfs2   # Fedora

# Mount:
sudo mount -t davfs http://localhost:5234/ /mnt/tuta-drive

# Auto-mount on login (no root required if user is in davfs2 group):
sudo usermod -aG davfs2 $USER
# then log out and back in, and mount without sudo

# /etc/fstab entry for manual mount:
http://localhost:5234/ /mnt/tuta-drive davfs noauto,user 0 0
```

Store your credentials in `/etc/davfs2/secrets` (or `~/.davfs2/secrets` for user mount):
```
http://localhost:5234/ your@tuta.com yourpassword
```

## rclone (recommended — no root required)

```bash
rclone config
# Type: WebDAV
# URL: http://localhost:5234/
# Vendor: Other
# User: your@tuta.com
# Password: your Tuta password

# List files:
rclone ls tuta-drive:

# Copy files:
rclone copy /local/path tuta-drive:folder/
rclone copy tuta-drive:folder/ /local/path
```

## GNOME Files (Nautilus)

Press `Ctrl+L` and enter: `dav://localhost:5234/`

Enter your Tuta email and password when prompted.

## Windows / macOS WebDAV

Map a network drive to `http://localhost:5234/`. On Windows use "Add a network location"
in File Explorer. On macOS use Finder → Go → Connect to Server.

## Supported operations

- **Browse** — list files and folders at any depth
- **Download** — GET individual files
- **Upload** — PUT files of any size (large files are split into 10 MB chunks automatically)
- **Create folders** — MKCOL
- **Delete** — files and folders (DELETE)
- **Rename** — rename a file or folder within the same location
- **Move** — move files or folders to a different location (MOVE)
- **LOCK/UNLOCK** — required by some WebDAV clients (davfs2, macOS); supported

## Upload notes

- Files larger than 10 MB are automatically split and uploaded in chunks.
- Uploads are retried up to 3 times on network errors.
- After a successful upload, the file is immediately visible in the local listing even if
  Tuta Drive's API hasn't propagated it yet (Tuta Drive has eventual consistency — a newly
  uploaded file may not appear in the API listing for a few seconds to a few minutes).
- davfs2 sometimes sends a second PUT if the first takes too long. The proxy deduplicates
  these: the second request sees the already-uploaded file and returns 201 without
  re-uploading.

## Known limitations

- Only one Tuta account per proxy instance.
- Maximum file size: 512 MB per upload.
- No TLS between the client and the proxy — traffic stays on localhost.
