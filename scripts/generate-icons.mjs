// Rasterizes web/apple-touch-icon.png from the favicon's shield mark.
// iOS home screens ignore SVG favicons and mask corners themselves, so the
// touch icon renders the mark on a full-bleed background (no rounded rect).
// Run: node scripts/generate-icons.mjs (uses the playwright Chromium already
// in devDependencies; no new packages).
import { chromium } from "@playwright/test";
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const size = 180;

const svg = await readFile(`${root}web/favicon.svg`, "utf8");
// Full-bleed variant: drop the rounded corners — iOS applies its own mask.
const bleed = svg.replace(/rx="18"/, "").replace(/viewBox="0 0 64 64"/, `viewBox="0 0 64 64" width="${size}" height="${size}"`);

const browser = await chromium.launch();
try {
  const page = await browser.newPage({ viewport: { width: size, height: size }, deviceScaleFactor: 1 });
  await page.setContent(
    `<!doctype html><style>html,body{margin:0;padding:0}</style>${bleed}`,
    { waitUntil: "load" }
  );
  const png = await page.locator("svg").screenshot({ type: "png" });
  await writeFile(`${root}web/apple-touch-icon.png`, png);
  console.log(`wrote web/apple-touch-icon.png (${png.length} bytes @${size})`);
} finally {
  await browser.close();
}
