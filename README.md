# HOSTIST

HOSTIST is a Discord-inspired community chat app built with Python, Flask, Flask-SocketIO, SQLite, HTML, CSS, and browser WebRTC.

## Included features

- User registration and login with hashed passwords
- Persistent SQLite accounts, servers, memberships, channels, messages, and direct messages
- Create multiple servers and switch between them
- Invite people to servers with a shareable invite link or invite code
- Create text and voice channels
- Real-time server text chat
- Add friends by username, accept incoming friend requests, and open one-to-one DMs
- Real-time private messaging with message history
- Start voice calls in voice channels and one-to-one DMs
- Microphone mute/unmute, deafen/undeafen, and leave-call controls
- Member list, online status, profile bio, and avatar upload
- Discord-inspired dark layout with responsive sidebars and friends view

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

6. Visit http://127.0.0.1:5000 and create an account. Create a second account in another browser/incognito window to test friend requests, DMs, and voice calls.

## Deploy on Render

The included `render.yaml` uses a persistent disk for the SQLite database and uploaded avatars. Push the contents of this folder to a GitHub repository, then create a Render Blueprint from that repository. Keep the persistent disk attached and use one service instance for this SQLite/in-memory voice-presence build.

The app reads `ABYSS_SECRET` and `ABYSS_DATA_DIR` from the environment; `render.yaml` configures both.

## Voice chat notes

Voice uses browser microphone access and peer-to-peer WebRTC with public Google STUN servers. Users must grant microphone permission, and the site must run on HTTPS (or localhost). The in-app controls support mute, deafen, and leave. Voice signaling and room membership are handled by Flask-SocketIO.

This is a small-community starter, not a production-grade voice service. Some networks require a TURN relay for reliable calls; no TURN service or credentials are included. The current peer-to-peer mesh is best for small rooms. For larger public rooms, use a dedicated SFU such as LiveKit, mediasoup, or Janus and configure a managed TURN service.

## Before public launch

This project still needs production hardening: CSRF protection, rate limiting, email verification, password reset, moderation/reporting, richer roles and permissions, upload scanning, backups, and a managed database/storage service for horizontal scaling. Voice presence is held in process memory, so run one app instance unless you add a shared presence store and Socket.IO message queue. Keep dependencies updated and set a strong secret in the hosting environment.
