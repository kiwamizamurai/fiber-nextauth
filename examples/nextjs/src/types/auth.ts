import { DefaultSession } from "next-auth";

export interface User {
  id: string;
  name: string;
  email: string;
}

declare module "next-auth" {
  interface Session {
    user: User & DefaultSession["user"];
  }
}

export interface ApiResponse {
  message: string;
  user: {
    name: string;
    email: string;
  };
} 