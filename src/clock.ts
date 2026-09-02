import type { Clock } from "./types.js";

export class SystemClock implements Clock {
  now(): Date {
    return new Date();
  }
}

export class FrozenClock implements Clock {
  constructor(private current: Date) {}

  now(): Date {
    return this.current;
  }

  advance(ms: number): void {
    this.current = new Date(this.current.getTime() + ms);
  }

  set(date: Date): void {
    this.current = date;
  }
}

export function iso(clock: Clock): string {
  return clock.now().toISOString();
}

export function addSeconds(clock: Clock, seconds: number): string {
  return new Date(clock.now().getTime() + seconds * 1000).toISOString();
}
