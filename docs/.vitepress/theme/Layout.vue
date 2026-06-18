<script setup lang="ts">
import DefaultTheme from "vitepress/theme";
import { useData, useRoute, useRouter, withBase } from "vitepress";
import { onMounted, watch } from "vue";

const { Layout } = DefaultTheme;
const { page } = useData();
const route = useRoute();
const router = useRouter();

// The #1090 refactor removed the Chinese i18n locale and the legacy
// `overview/*` / `*/readme` URL scheme. Old bookmarks and search results
// still point at those paths, so map them to the new structure on 404.
const EXACT: Record<string, string> = {
  "/overview/home": "/",
  "/overview/architecture": "/architecture/",
  "/overview/credential-vault": "/guides/credential-vault",
  "/overview/release-verification": "/community/release-verification",
  "/design/single-host-network": "/architecture/single-host-network",
  "/single_host_network": "/architecture/single-host-network",
  "/kubernetes/development": "/kubernetes/deployment",
  "/server/readme": "/components/server",
  "/specs/readme": "/api/",
  "/secure-container": "/guides/secure-container",
  "/pause-resume": "/guides/pause-resume",
  "/execd-path-migration": "/reference/execd-path-migration",
};

// Returns a base-relative best-effort target for a 404 path. The result may
// itself not exist; the caller falls back to the home page only once a fully
// cleaned path still 404s, so legacy URLs that match a current page (e.g.
// /zh/community/contributing) reach it instead of collapsing to home.
function resolveLegacy(rawPath: string): string {
  const base = import.meta.env.BASE_URL.replace(/\/$/, "");
  let p = rawPath.slice(base.length).replace(/\.html$/, "").replace(/\/$/, "").toLowerCase();
  p = p.replace(/^\/zh(?=\/|$)/, "");
  if (p === "" || p === "/") return "/";
  if (EXACT[p]) return EXACT[p];
  if (p.startsWith("/oseps/")) return "/community/oseps";
  p = p.replace("/sdks/sandbox/", "/sdks/").replace(/\/(readme|development)$/, "");
  return p || "/";
}

function maybeRedirect() {
  if (!page.value.isNotFound) return;
  const target = resolveLegacy(window.location.pathname);
  // Avoid looping when an already-clean path still 404s; send it home.
  if (withBase(target) === window.location.pathname) {
    if (target !== "/") router.go(withBase("/"));
    return;
  }
  router.go(withBase(target));
}

onMounted(maybeRedirect);
// Watch the path (not just isNotFound) so a redirect that lands on another
// missing route re-evaluates and reaches the home fallback instead of sticking.
watch(() => route.path, maybeRedirect);
</script>

<template>
  <Layout />
</template>
