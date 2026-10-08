import type { Metadata } from "next";
import "./globals.css";
import { MobileDeviceGate } from "@/components/MobileDeviceGate";

export const metadata: Metadata = {
  title: "Hacker — Security Testing Platform",
  description: "Authorized web application security testing.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="font-sans antialiased">
        <MobileDeviceGate>{children}</MobileDeviceGate>
      </body>
    </html>
  );
}
