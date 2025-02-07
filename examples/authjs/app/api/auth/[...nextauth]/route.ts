import NextAuth from "next-auth";
import type { NextAuthConfig } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";

const config = {
  providers: [
    CredentialsProvider({
      name: "Credentials",
      credentials: {
        username: { label: "Username", type: "text" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials) {
        const validCredentials = {
          username: "demo",
          password: "demo"
        };

        if (
          credentials?.username === validCredentials.username &&
          credentials?.password === validCredentials.password
        ) {
          return {
            id: "5",
            name: "v5 User",
            email: "v5@example.com",
          };
        }
        return null;
      },
    }),
  ],
  session: {
    strategy: "jwt",
  },
} satisfies NextAuthConfig;

export const { auth, handlers: { GET, POST } } = NextAuth(config); 