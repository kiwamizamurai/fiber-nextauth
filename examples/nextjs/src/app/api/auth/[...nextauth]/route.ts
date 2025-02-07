import NextAuth from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";

const handler = NextAuth({
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
            id: "4",
            name: "v4 User",
            email: "v4@example.com",
          };
        }
        return null;
      },
    }),
  ],
  session: {
    strategy: "jwt",
  },
});

export { handler as GET, handler as POST }; 