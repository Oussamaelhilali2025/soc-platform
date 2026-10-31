"use client";

import { RBACProvider } from "./RBACContext";

export default function Providers({ children }) {
  return <RBACProvider>{children}</RBACProvider>;
}