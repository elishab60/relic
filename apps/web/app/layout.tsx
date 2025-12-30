import type { Metadata } from "next";
import "./globals.css";
import { BootProvider } from "@/components/BootProvider";

export const metadata: Metadata = {
    title: "Relic",
    description: "AI-Assisted Web Security Auditor",
};

export default function RootLayout({
    children,
}: Readonly<{
    children: React.ReactNode;
}>) {
    return (
        <html lang="en" className="dark">
            <body>
                <BootProvider>
                    {children}
                </BootProvider>
            </body>
        </html>
    );
}
