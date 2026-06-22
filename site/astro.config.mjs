// @ts-check
import { defineConfig } from "astro/config";
import tailwind from "@astrojs/tailwind";
import sitemap from "@astrojs/sitemap";

// https://astro.build
export default defineConfig({
  site: "https://trypalisade.dev",
  integrations: [tailwind(), sitemap()],
});
