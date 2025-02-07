"use client";

import { signIn, signOut, useSession } from "next-auth/react";
import { useState } from "react";

export default function Home() {
  const { data: session } = useSession();
  const [response, setResponse] = useState<string>("");

  const handleTestClick = async () => {
    try {
      const res = await fetch("http://localhost:3000/v5/test", {
        credentials: "include",
      });
      console.log("Response status:", res.status);
      if (!res.ok) {
        const errorText = await res.text();
        console.error("Error response:", errorText);
        throw new Error(`HTTP error! status: ${res.status}`);
      }
      const data = await res.json();
      setResponse(JSON.stringify(data, null, 2));
    } catch (error: any) {
      console.error("Fetch error:", error);
      setResponse(`Error fetching data: ${error?.message || 'Unknown error'}`);
    }
  };

  if (!session) {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center">
        <button
          onClick={() => signIn()}
          className="rounded bg-blue-500 px-4 py-2 text-white hover:bg-blue-600"
        >
          Sign in
        </button>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-4">
      <div>Signed in as {session.user?.email}</div>
      <pre className="rounded bg-gray-100 p-4">
        <code>{JSON.stringify(session, null, 2)}</code>
      </pre>
      <button
        onClick={handleTestClick}
        className="rounded bg-blue-500 px-4 py-2 text-white hover:bg-blue-600"
      >
        Test Fiber Backend
      </button>
      {response && (
        <pre className="rounded bg-gray-100 p-4">
          <code>{response}</code>
        </pre>
      )}
      <button
        onClick={() => signOut()}
        className="rounded bg-red-500 px-4 py-2 text-white hover:bg-red-600"
      >
        Sign out
      </button>
    </div>
  );
}
