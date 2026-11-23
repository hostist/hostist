# HOSTIST

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
