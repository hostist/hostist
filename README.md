# HOSTIST

HOSTIST is a Discord-inspired, self-hosted community chat starter made with Python, Flask, Flask-SocketIO, SQLite, HTML, CSS, and browser WebRTC.

## Run locally

1. Install Python 3.10+.
2. Extract this folder.
3. In a terminal opened inside the folder, run:

   ```bash
   python -m venv .venv
   ```

   Windows:
   ```powershell
   .venv\Scripts\activate
   ```

   macOS/Linux:
   ```bash
   source .venv/bin/activate
   ```

4. Install packages:

   ```bash
   pip install -r requirements.txt
   ```

5. Start HOSTIST:

   ```bash
   python app.py
   ```

6. Visit http://127.0.0.1:5000 and create an account.

## Features in this build

- User registration and login with hashed passwords
- Persistent SQLite storage
- Create servers and text/voice channels
- Invite codes to join servers
- Real-time text chat
- Friend requests and one-to-one direct messages
- Profile bio and avatar upload
- Online/offline status indicator
- Home button opens the Friends and Direct Messages workspace (Discord-style)
- Separate Servers navigation rail
- Bottom user menu with remembered account names and password-required account switching
- Basic server roles (owner/member)
- Browser voice chat prototype using WebRTC peer connections

## Voice chat notes

Voice uses browser microphone access and WebRTC with a public STUN server. It works best on `localhost` or an HTTPS deployment, and users must grant microphone permission. Some NAT/firewall combinations require a TURN server, which is not bundled. The current voice implementation is a basic peer-to-peer mesh prototype, not Discord-grade voice infrastructure.

## Important security and production limitations

This is a functional starter, not a production-ready Discord replacement. Before exposing it publicly:
- Set a strong random `HOSTIST_SECRET` environment variable.
- Run behind HTTPS and a production server configured for Flask-SocketIO.
- Add CSRF protection, rate limiting, email verification, password reset, moderation/reporting, server ownership transfer, richer role/permission controls, and abuse prevention.
- Configure secure upload scanning and limits.
- Use a TURN service for reliable voice connectivity.
- Add proper presence tracking across multiple browser sessions and a persistent Socket.IO deployment adapter for multiple app workers.

The app is intended for local development and small private communities.


## Interface refresh
The Friends workspace now follows a Discord-inspired black layout with a conversation search,
Friends and Message Requests navigation, a separate DM list, an Active Now panel, and a
profile popover opened from the signed-in user control at the bottom of the sidebar.
The Servers workspace remains separate in the left server rail.

## Loading-speed improvements in this build

- The Socket.IO client script is loaded after the page markup so it does not block the initial layout from rendering.
- The stylesheet URL is versioned and static assets receive a browser cache lifetime, reducing repeat-download time.
- Server pages only load server-member and channel-message data; Friends pages only load friends, requests, and DM data.
- Initial channel and DM history is limited to the latest 60 messages to keep page rendering lighter.
- SQLite uses WAL mode, a short busy timeout, a page cache, and indexes for common membership, friendship, channel, and DM lookups.

These changes reduce avoidable work, but actual speed still depends on the Render instance, database size, network, and browser. Render free instances may sleep when idle; code changes cannot remove that cold-start delay.

## Account registration and username ownership

- New users must create an account with a username and password before using HOSTIST.
- Usernames are unique without regard to capitalization, so `Host`, `host`, and `HOST` refer to the same claimed name.
- Registration asks users to confirm their password and requires at least 8 characters.
- Passwords are stored as Werkzeug password hashes, never as plain text.
- Logging in requires the correct password; knowing an existing username is not enough to access its account.

## Deployment persistence (important)

For Render, deploy updates to the **same existing web service** and keep its persistent disk attached at `/var/data`. The included `render.yaml` sets `ABYSS_DATA_DIR=/var/data` and creates `ABYSS_SECRET` once for the service. Do not delete/recreate the service or its disk when publishing a code update.

This build automatically uses `/var/data` when it detects the Render disk, even if `ABYSS_DATA_DIR` was accidentally omitted. If it finds an older `abyss.db` and `uploads/` beside `app.py` while the persistent disk has no database yet, it copies them to the disk once. It never overwrites a database already on the disk. The session-signing key is also kept on the persistent disk when `ABYSS_SECRET` is not configured.

After deployment, check the Render logs for `HOSTIST persistent data directory: /var/data`. If the persistent database and uploads were already deleted by an earlier deployment and there is no backup or attached old disk, this code cannot reconstruct those lost accounts; attach/restore the old disk or database backup before starting with an empty volume.
