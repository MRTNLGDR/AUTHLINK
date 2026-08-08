import type { ReactNode } from 'react';

export function Glyph({ children, tone = 'green' }: { children: ReactNode; tone?: 'green' | 'blue' | 'amber' | 'red' }) {
  return <span className={`glyph glyph-${tone}`}>{children}</span>;
}

export const icons = {
  home: '⌂',
  chat: '◌',
  apps: '⊞',
  match: '♡',
  profile: '♙',
  shield: '⬡',
  key: '⌘',
  photo: '▧',
  bell: '◉',
  search: '⌕',
  lock: '▣',
  network: '⌬',
  warning: '!',
  device: '▯',
  cloud: '☁',
  code: '</>',
};
