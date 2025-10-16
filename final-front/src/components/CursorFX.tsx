import React, { useEffect, useRef } from "react";
import { createPortal } from "react-dom";

export default function CursorFX() {
  const dot = useRef<HTMLDivElement>(null);
  const ring = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const root = document.documentElement;
    const move = (e: PointerEvent) => {
      root.style.setProperty("--x", e.clientX + "px");
      root.style.setProperty("--y", e.clientY + "px");
    };
    const down = () => document.body.classList.add("cursor-down");
    const up   = () => document.body.classList.remove("cursor-down");

    window.addEventListener("pointermove", move, { passive: true });
    window.addEventListener("pointerdown", down, { passive: true });
    window.addEventListener("pointerup",   up,   { passive: true });
    return () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerdown", down);
      window.removeEventListener("pointerup",   up);
    };
  }, []);

  return createPortal(
    <>
      <div className="c-dot"  ref={dot}  />
      <div className="c-ring" ref={ring} />
    </>,
    document.body
  );
}