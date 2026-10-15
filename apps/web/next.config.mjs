/** @type {import('next').NextConfig} */
const configuredApiOrigin = process.env.API_ORIGIN ?? "http://localhost:4000";
const apiOrigin = configuredApiOrigin.startsWith("http")
  ? configuredApiOrigin
  : `http://${configuredApiOrigin}`;

const nextConfig = {
  reactStrictMode: true,
  async rewrites() {
    return [
      { source: "/api/:path*", destination: `${apiOrigin}/api/:path*` },
    ];
  },
};
export default nextConfig;
