/**
 * @fileoverview Module-level canvas accessor for DataCanvas integration.
 * Wire via `setCanvas(core.canvas)` in the createApp setup() callback.
 * @module services/canvas/canvas-accessor
 */

import type { DataCanvas } from '@cyanheads/mcp-ts-core/canvas';

let _canvas: DataCanvas | undefined;

/** Store the DataCanvas instance from core. Called once in setup(). */
export function setCanvas(canvas: DataCanvas | undefined): void {
  _canvas = canvas;
}

/** Retrieve the DataCanvas instance, or undefined when canvas is not enabled. */
export function getCanvas(): DataCanvas | undefined {
  return _canvas;
}
