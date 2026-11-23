HOSTIST — PUBLIC HOSTING SETUP (Hostist / Render)

This package is configured to be hosted publicly. It does not become public just by running app.py on your PC.

1. Create/sign in to a Render account: https://render.com/
2. Create a new GitHub repository and upload the contents of this folder (app.py, requirements.txt, templates/, static/, render.yaml).
3. In Render, choose New + -> Blueprint and connect that GitHub repository.
4. Render reads render.yaml (service name: hostist) and creates the web service with a persistent disk and generated secret.
5. Wait for deployment to finish. Open the public *.onrender.com URL shown by Render and share it.

Important:
- Keep the persistent disk enabled. It stores user accounts, messages, and uploaded avatars.
- Use one service instance for this SQLite version. Multiple instances need a shared database and shared upload storage.
- The included voice chat uses browser WebRTC. Users need microphone permission; some networks require a TURN relay server for reliable voice.
- This is an early prototype, not a production-hardened Discord replacement. Before a large public launch, add CSRF protection, rate limits, stronger moderation/admin tools, backups, and a managed database/storage service.
- The free hosting tier may sleep or lack persistent disks; the included configuration uses a paid persistent-disk service.
