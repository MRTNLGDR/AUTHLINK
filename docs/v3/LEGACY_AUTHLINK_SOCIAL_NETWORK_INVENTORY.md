# Legacy import — `authlink-social-network.rar`

The legacy archive inspected during the AuthLink V3 design is preserved as a **capability source**, not as the new UX shell.

## What must survive in V3

### Settings / platform management

- billing;
- data visualization;
- event logs;
- feature flags;
- profile;
- notifications;
- generic settings;
- GitHub integration;
- GitLab integration;
- MCP server management;
- module management;
- Netlify integration;
- Vercel integration;
- Supabase integration;
- local AI providers;
- cloud AI providers;
- sequencer configuration.

### Chat / AI workspace

- API key manager;
- artifact viewer;
- contextual Ask/assistant panel;
- assistant/user messages;
- chat alerts;
- chat export/import;
- code blocks and Markdown;
- file preview;
- Git clone/import;
- model selector;
- MCP tools and tool invocation viewer;
- speech recognition;
- starter templates;
- thought/progress panels;
- deployment links;
- screenshot state management.

### Developer/deploy

- GitHub deploy;
- GitLab deploy;
- Netlify deploy;
- Vercel deploy;
- deployment dialogs/status;
- Git URL import.

### Editor / workbench

- CodeMirror editor;
- binary content viewer;
- env masking;
- language detection;
- diff view;
- file tree;
- breadcrumbs;
- inspector;
- preview;
- screenshot selector;
- project search;
- file locks;
- port selector;
- workbench shell.

### Notes / modules / sequencer

- Notes Workspace;
- checklist;
- modules library;
- module preview/completion;
- sequence planning;
- sequence builder;
- sequence workspace;
- validation/run status/timeline.

### Existing route/API families found

UI routes included dashboard, chat, git, modules, notes, preview, sequencer builder and webcontainer connect/preview.

Backend route families included:

- billing/meters/status;
- chat/LLM/embeddings;
- provider/API-key configuration;
- GitHub/GitLab;
- knowledge-base search;
- local model discovery;
- MCP;
- modules install/update/remove/test/sync/deploy;
- Netlify/Vercel;
- notes;
- observability;
- policy;
- sequencer;
- Supabase projects/schema/query/logs/backup/sync;
- system diagnostics and disk/git info.

## V3 placement

These capabilities live under:

```text
Apps
└─ Developer
   ├─ AI Providers
   ├─ MCP
   ├─ Git
   ├─ Deploy
   ├─ Modules
   ├─ Sequencer
   ├─ Notes
   ├─ Workbench
   ├─ Preview
   ├─ Data / Supabase compatibility
   ├─ Event Logs
   └─ Billing / Feature flags
```

They do **not** replace Feed/Chat/Apps/Match/Profile as the primary mobile navigation.

## Import rule

Do not copy `.env.local`, `.env.production`, API keys, tokens or cached user data from the archive. Reuse components only after dependency/license/security review. Secrets migrate to OS keystore/server secret manager and are represented in the UI only by `SecretRef`.
