"use client";

import { useEffect, useState } from "react";

export function MobileDeviceGate({ children }: { children: React.ReactNode }) {
  const [isMobile, setIsMobile] = useState(false);

  useEffect(() => {
    const check = () => {
      const isMobileUA = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(
        navigator.userAgent,
      );
      const isSmallScreen = window.innerWidth <= 820;
      setIsMobile(isMobileUA || isSmallScreen);
    };
    check();
    window.addEventListener("resize", check);
    return () => window.removeEventListener("resize", check);
  }, []);

  return (
    <>
      <div
        id="mobile-device-warning"
        className={`${
          isMobile ? "flex" : "hidden"
        } min-h-screen w-full items-center justify-center p-8 bg-[#fafaf8] text-center select-none`}
      >
        <p className="text-2xl sm:text-3xl font-extrabold text-[#151924] leading-relaxed max-w-xl">
          This app is unavailable on mobile phones. Open it on your laptop device or Personal desktop computer.
        </p>
      </div>
      <div id="desktop-app-root" className={isMobile ? "hidden" : "contents"}>
        {children}
      </div>
    </>
  );
}
