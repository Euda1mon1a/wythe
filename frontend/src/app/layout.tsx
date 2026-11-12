import type { Metadata } from 'next';
import { Providers } from '@/components/Providers';
import './globals.css';

export const metadata: Metadata = {
  title: 'Wythe — Why -> Therefore · 3-Tier Architecture Verifier',
  description:
    'PostgreSQL holds truth · Backend manipulates truth · UI displays truth',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <body className="min-h-screen selection:bg-teal-500/30 selection:text-teal-200">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
