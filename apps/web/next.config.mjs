/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  async rewrites() {
    return [
      { source: "/api/:path*", destination: `${process.env.API_ORIGIN ?? "http://localhost:4000"}/api/:path*` },
    ];
  },
};
export default nextConfig;
