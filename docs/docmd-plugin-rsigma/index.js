import fs from "node:fs";
import path from "node:path";
import sharp from "sharp";
import { parse as parseYaml } from "yaml";

/** @type {Record<string, unknown> | null} */
let rsigmaVars = null;
/** @type {Map<string, string> | null} */
let releases = null;
/** @type {string | null} */
let repoRoot = null;
/** Published site origin and base path, from the resolved docmd config. */
let siteUrl = "https://rsigma.io/";
let siteBase = "/";

/**
 * Walk up from a starting directory until we find the workspace `Cargo.toml`
 * (the repository root). The docmd project lives under `docs/`, so the repo
 * root is a parent of the current working directory.
 *
 * @param {string} startDir
 * @returns {string}
 */
function findRepoRoot(startDir) {
  let dir = path.resolve(startDir);
  for (;;) {
    if (fs.existsSync(path.join(dir, "Cargo.toml"))) {
      return dir;
    }
    const parent = path.dirname(dir);
    if (parent === dir) {
      return path.resolve(startDir);
    }
    dir = parent;
  }
}

/**
 * @param {string} root Repository root (directory containing Cargo.toml).
 * @returns {Record<string, unknown>}
 */
function loadRsigmaVars(root) {
  const cargoPath = path.join(root, "Cargo.toml");
  const varsPath = path.join(root, "docs", "_data", "vars.yml");
  const cargoText = fs.readFileSync(cargoPath, "utf8");
  const staticVars = parseYaml(fs.readFileSync(varsPath, "utf8"));

  const pkg = {};
  const inWorkspacePackage = cargoText.match(
    /\[workspace\.package\]([\s\S]*?)(?:\n\[|\n*$)/,
  );
  if (inWorkspacePackage) {
    for (const line of inWorkspacePackage[1].split("\n")) {
      const m = line.match(/^(\w[\w-]*) = "(.*)"\s*$/);
      if (m) {
        pkg[m[1]] = m[2];
      }
    }
  }

  const members = cargoText.match(/^members = \[([\s\S]*?)\]/m);
  const crateCount = members ? [...members[1].matchAll(/"[^"]+"/g)].length : undefined;

  const rsigma = {
    ...(staticVars.rsigma ?? {}),
    version: pkg.version,
    edition: pkg.edition,
    msrv: pkg["rust-version"],
    license: pkg.license,
    crate_count: crateCount,
  };

  return { rsigma };
}

/**
 * @param {Record<string, unknown>} vars
 * @param {string} dottedPath
 * @returns {unknown}
 */
function getVar(vars, dottedPath) {
  return dottedPath.split(".").reduce((obj, key) => {
    if (obj && typeof obj === "object" && key in obj) {
      return /** @type {Record<string, unknown>} */ (obj)[key];
    }
    return undefined;
  }, /** @type {unknown} */ (vars));
}

/**
 * @param {unknown} value
 * @param {string | undefined} search
 * @param {string | undefined} replaceWith
 * @returns {string}
 */
function applyReplaceFilter(value, search, replaceWith) {
  const text = String(value ?? "");
  if (search === undefined || replaceWith === undefined) {
    return text;
  }
  return text.split(search).join(replaceWith);
}

/**
 * @param {string} src
 * @param {Record<string, unknown>} vars
 * @returns {string}
 */
function substituteRsigmaMacros(src, vars) {
  return src.replace(
    /\{\{\s*rsigma\.([\w.]+)\s*(?:\|\s*replace\("([^"]*)",\s*"([^"]*)"\))?\s*\}\}/g,
    (_match, dottedPath, search, replaceWith) =>
      applyReplaceFilter(getVar(vars, `rsigma.${dottedPath}`), search, replaceWith),
  );
}

/**
 * Read the released versions from `CHANGELOG.md` headings
 * (`## [X.Y.Z] - YYYY-MM-DD`), keyed by version with the release date.
 *
 * @param {string} root Repository root.
 * @returns {Map<string, string>}
 */
function loadReleases(root) {
  const text = fs.readFileSync(path.join(root, "CHANGELOG.md"), "utf8");
  const releases = new Map();
  for (const m of text.matchAll(/^## \[(\d+\.\d+\.\d+)\] - (\d{4}-\d{2}-\d{2})\s*$/gm)) {
    releases.set(m[1], m[2]);
  }
  return releases;
}

/**
 * Heading id docmd assigns to a version section on the release-notes page,
 * which inlines the changelog under its `# Changelog` title.
 *
 * @param {string} version `X.Y.Z` or `unreleased`
 * @param {Map<string, string>} releases
 * @returns {string}
 */
function releaseAnchor(version, releases) {
  if (version === "unreleased") {
    return "changelog-unreleased";
  }
  return `changelog-${version.replaceAll(".", "")}-${releases.get(version)}`;
}

/** Anchors emitted by version tags, checked against the built release notes. */
const emittedReleaseAnchors = new Set();

/**
 * Expand `{{ added "X.Y.Z" }}` and `{{ added "unreleased" }}` into docmd
 * inline tags linking to the matching release-notes section. Fenced code
 * blocks and inline code spans are left alone so the syntax can be quoted.
 *
 * docmd does not rebase tag URLs for its pretty-URL output the way it does
 * Markdown links, and it calls `onBeforeParse` for the home page without a
 * file path, so the link is rooted at the site base rather than page-relative.
 *
 * Each tag is closed with `:::` so text after it on the same line stays
 * outside the tag. docmd only honors that terminator when whitespace or the end
 * of the line follows it, so a tag directly followed by punctuation is an error.
 *
 * @param {string} src
 * @param {string} page Page path for error messages.
 * @param {Map<string, string>} releases
 * @returns {string}
 */
function expandVersionTags(src, page, releases) {
  if (!/\{\{\s*added\s/.test(src)) {
    return src;
  }
  const tagRe = /\{\{\s*added\s+"([^"]+)"\s*\}\}/g;
  const notes = `${siteBase.endsWith("/") ? siteBase : `${siteBase}/`}release-notes/`;
  const render = (match, version, offset, text) => {
    const next = text.charAt(offset + match.length);
    if (next && !/\s/.test(next)) {
      throw new Error(
        `docmd-plugin-rsigma: ${page} has "${next}" directly after {{ added "${version}" }}; put whitespace or a line end after the tag`,
      );
    }
    if (version !== "unreleased" && !releases.has(version)) {
      throw new Error(
        `docmd-plugin-rsigma: ${page} tags unknown version "${version}"; use a released X.Y.Z from CHANGELOG.md or "unreleased"`,
      );
    }
    const anchor = releaseAnchor(version, releases);
    emittedReleaseAnchors.add(anchor);
    return version === "unreleased"
      ? `::: tag "Unreleased" icon:flask-conical color:#d97706 url:"${notes}#${anchor}" :::`
      : `::: tag "Added in v${version}" icon:tag url:"${notes}#${anchor}" :::`;
  };
  const skipRe = /(`+[^`]*`+)/;
  let inFence = false;
  return src
    .split("\n")
    .map((line) => {
      const t = line.trimStart();
      if (t.startsWith("```") || t.startsWith("~~~")) {
        inFence = !inFence;
        return line;
      }
      if (inFence) {
        return line;
      }
      return line
        .split(skipRe)
        .map((seg) => (seg.startsWith("`") ? seg : seg.replace(tagRe, render)))
        .join("");
    })
    .join("\n");
}

/**
 * @param {string} src
 * @param {string} filePath
 * @param {string} projectRoot
 * @returns {string}
 */
function inlineIncludeMarkdown(src, filePath, projectRoot) {
  const includeRe =
    /\{%\s*include-markdown\s+"([^"]+)"\s*%\}/g;
  return src.replace(includeRe, (_match, relPath) => {
    const baseDir = path.dirname(filePath);
    const target = path.resolve(baseDir, relPath);
    const relToRoot = path.relative(projectRoot, target);
    if (relToRoot.startsWith("..") || path.isAbsolute(relToRoot)) {
      throw new Error(
        `include-markdown target escapes project root: ${relPath} from ${filePath}`,
      );
    }
    return fs.readFileSync(target, "utf8").trimEnd();
  });
}

/**
 * Turn GitHub issue/PR shorthand (`#123`) into links, matching the old
 * MkDocs `pymdownx.magiclink` behaviour. Skips fenced code blocks and inline
 * code spans, and leaves already-linked references (`[#123](...)`) untouched.
 * `/issues/N` redirects to `/pull/N` for pull requests, so it resolves for both.
 *
 * @param {string} md
 * @param {string} repoUrl e.g. https://github.com/timescale/rsigma
 * @returns {string}
 */
function linkifyIssueRefs(md, repoUrl) {
  const base = `${repoUrl.replace(/\/$/, "")}/issues/`;
  // Not preceded by a word char, `[` (existing link text), `#`, `&`, or `/`
  // (URL path/entity); followed by digits ending on a word boundary.
  const issueRe = /(?<![\w[#&/])#(\d+)\b/g;
  // `#N` tokens whose immediately preceding word marks an external reference
  // (a newsletter issue or a SigmaHQ spec proposal), not an rsigma issue/PR.
  const excludeBefore = [
    /\bweekly\s*$/i, // Detection Engineering Weekly #N
    /\bdew\s*$/i, // DEW #N
    /\bsec\s*$/i, // tl;dr sec #N
    /\bnewsletter\s*$/i,
    /\bblacknoise\s*$/i,
    /\bsep\s*$/i, // Sigma Enhancement Proposal #N
    /\bdiscussion\s*$/i, // SigmaHQ spec Discussion #N
    /\bspecification\s*$/i, // (sigma-)specification #N
  ];
  // Split out inline code spans and existing markdown links so `#N` inside
  // them (e.g. `[issue #158](...)`, `[SEP #212](...)`) is never rewritten.
  const skipRe = /(`+[^`]*`+|\[[^\]]*\]\([^)]*\))/;
  const linkInline = (text) =>
    text
      .split(skipRe)
      .map((seg) => {
        if (!seg || seg.startsWith("`") || seg.startsWith("[")) return seg;
        return seg.replace(issueRe, (m, n, offset, str) =>
          excludeBefore.some((re) => re.test(str.slice(0, offset)))
            ? m
            : `[#${n}](${base}${n})`,
        );
      })
      .join("");
  let inFence = false;
  return md
    .split("\n")
    .map((line) => {
      const t = line.trimStart();
      if (t.startsWith("```") || t.startsWith("~~~")) {
        inFence = !inFence;
        return line;
      }
      return inFence ? line : linkInline(line);
    })
    .join("\n");
}

/**
 * Render inline-code spans (`` `code` ``) in an already-HTML-escaped string as
 * `<code>` elements. Used where HTML renders (the visible header title).
 *
 * @param {string} escaped
 * @returns {string}
 */
function inlineCodeToHtml(escaped) {
  return escaped.replace(/`([^`]+)`/g, "<code>$1</code>");
}

/**
 * Drop inline-code backticks, keeping the inner text. Used in plain-text
 * contexts (`<title>`, Open Graph / Twitter meta) where HTML does not render.
 *
 * @param {string} text
 * @returns {string}
 */
function stripInlineCode(text) {
  return text.replace(/`([^`]+)`/g, "$1");
}

/**
 * docmd derives the page title from the first Markdown H1 but keeps the raw
 * text, so a heading like `` # `rsigma engine discover-schemas` `` leaves
 * literal backticks in the header bar, the focus-mode title, the `<title>`, and
 * the social meta. Fix that after render: the visible titles render the code
 * span as `<code>` (matching the in-body H1), and the plain-text `<title>` / meta strip the
 * markers. Pages whose title has no backticks are left untouched.
 *
 * @param {string} html
 * @returns {string}
 */
function renderMarkdownTitles(html) {
  let out = html.replace(
    /(<span class="header-title">)([\s\S]*?)(<\/span>)/,
    (match, open, inner, close) =>
      inner.includes("`") ? `${open}${inlineCodeToHtml(inner.trim())}${close}` : match,
  );
  out = out.replace(
    /(<h1 class="docmd-focus-title">)([\s\S]*?)(<\/h1>)/,
    (match, open, inner, close) =>
      inner.includes("`") ? `${open}${inlineCodeToHtml(inner.trim())}${close}` : match,
  );
  out = out.replace(
    /(<title>)([\s\S]*?)(<\/title>)/,
    (match, open, inner, close) =>
      inner.includes("`") ? `${open}${stripInlineCode(inner)}${close}` : match,
  );
  out = out.replace(
    /(<meta (?:property="og:title"|name="twitter:title") content=")([^"]*)(">)/g,
    (match, open, content, close) =>
      content.includes("`") ? `${open}${stripInlineCode(content)}${close}` : match,
  );
  return out;
}

/**
 * Set Google Consent Mode before docmd's GA4 script runs, then connect it to
 * docmd's cookie-consent event. Advertising consent remains denied because the
 * site only uses analytics.
 *
 * @param {string} html
 * @returns {string}
 */
function injectAnalyticsConsentMode(html) {
  const ga4Marker = "    <!-- GA4 -->";
  let out = html.replace(
    /(<script async src="https:\/\/www\.googletagmanager\.com\/gtag\/js\?id=)"(G-[A-Z0-9]{6,12})"("><\/script>)/,
    "$1$2$3",
  );
  if (!out.includes(ga4Marker) || out.includes("RSigma GA4 consent mode")) {
    return out;
  }
  const consentScript = `    <!-- RSigma GA4 consent mode -->
    <script>
      window.dataLayer = window.dataLayer || [];
      window.gtag = window.gtag || function(){dataLayer.push(arguments);};
      (function() {
        var analyticsConsent = 'denied';
        try {
          var raw = localStorage.getItem('docmd-cookie-consent');
          var choice = raw ? JSON.parse(raw) : null;
          if (choice && choice.value === 'accept' && choice.expires > Date.now()) {
            analyticsConsent = 'granted';
          }
        } catch (_) {}
        gtag('consent', 'default', {
          ad_storage: 'denied',
          ad_user_data: 'denied',
          ad_personalization: 'denied',
          analytics_storage: analyticsConsent
        });
        window.addEventListener('docmd:cookie-consent', function(event) {
          gtag('consent', 'update', {
            ad_storage: 'denied',
            ad_user_data: 'denied',
            ad_personalization: 'denied',
            analytics_storage: event.detail.value === 'accept' ? 'granted' : 'denied'
          });
        });
      })();
    </script>
`;
  return out.replace(ga4Marker, `${consentScript}${ga4Marker}`);
}

/** Legacy generated/copied brand files to remove when refreshing assets. */
const STALE_BRAND_FILES = [
  "sidebar-logo.svg",
  "logo-dark.png",
  "favicon-dark.png",
  "favicon.svg",
  "rsigma-logotype.svg",
  "rsigma-logo.svg",
  "rsigma-logotype.png",
];

/** Repo-root `assets/` files copied into the site so pages can embed them. */
const COPIED_ASSETS = ["detection-loop.svg", "architecture.svg", "internal_architecture.svg"];

/**
 * The repo copy of an SVG links to the published site with absolute URLs so
 * it still works when opened on its own (GitHub "Raw", a local file). Inside
 * the docs those links must follow the host serving the build instead, so the
 * site origin is rewritten to the configured base path.
 *
 * @param {Buffer} data
 * @returns {Buffer}
 */
function relinkToSiteBase(data) {
  const origin = siteUrl.endsWith("/") ? siteUrl : `${siteUrl}/`;
  const base = siteBase.endsWith("/") ? siteBase : `${siteBase}/`;
  return Buffer.from(data.toString("utf8").replaceAll(`href="${origin}`, `href="${base}`), "utf8");
}

/** @type {{ svg: string, images: Record<string, Buffer> } | null} */
let brandImageCache = null;

/**
 * Render the brand image set from the logo SVG: the sidebar logo (one image
 * serves both themes; the mark's orange facets carry it on any background, and
 * the dark theme adds a darker backing in CSS) plus a square PNG favicon.
 * Memoised on the SVG source so repeated builds in one `docmd dev` session
 * rasterise once.
 *
 * @param {string} logoSvgPath
 * @returns {Promise<Record<string, Buffer>>}
 */
async function renderBrandImages(logoSvgPath) {
  const svg = fs.readFileSync(logoSvgPath, "utf8");
  if (brandImageCache && brandImageCache.svg === svg) {
    return brandImageCache.images;
  }

  const mark = await sharp(Buffer.from(svg), { density: 192 })
    .trim()
    .png()
    .toBuffer({ resolveWithObject: true });

  const logo = await sharp(mark.data)
    .resize({ height: 512, withoutEnlargement: true })
    .png()
    .toBuffer();

  // Pad to a square in one pipeline, then resize in another: sharp applies
  // resize before extend within a single pipeline, so they must be separate.
  const square = Math.max(mark.info.width, mark.info.height);
  const squareBuf = await sharp(mark.data)
    .extend({
      top: Math.floor((square - mark.info.height) / 2),
      bottom: Math.ceil((square - mark.info.height) / 2),
      left: Math.floor((square - mark.info.width) / 2),
      right: Math.ceil((square - mark.info.width) / 2),
      background: { r: 0, g: 0, b: 0, alpha: 0 },
    })
    .png()
    .toBuffer();
  const favicon = await sharp(squareBuf).resize(256, 256).png().toBuffer();

  const images = { "logo.png": logo, "favicon.png": favicon };
  brandImageCache = { svg, images };
  return images;
}

/**
 * Write a file only when its bytes differ from what is already on disk.
 * `docmd dev` watches `docs/assets/` and keys its change detection on
 * mtime, so an unconditional rewrite of an identical file starts a build
 * loop that never settles.
 *
 * @param {string} filePath
 * @param {Buffer} data
 */
function writeIfChanged(filePath, data) {
  try {
    if (fs.readFileSync(filePath).equals(data)) {
      return;
    }
  } catch {
    // Missing or unreadable: fall through and write.
  }
  fs.writeFileSync(filePath, data);
}

/**
 * @param {string} destDir
 * @param {string} logoSvgPath
 */
async function writeBrandImages(destDir, logoSvgPath) {
  fs.mkdirSync(destDir, { recursive: true });
  const images = await renderBrandImages(logoSvgPath);
  for (const [name, data] of Object.entries(images)) {
    writeIfChanged(path.join(destDir, name), data);
  }

  const assetsDir = path.dirname(logoSvgPath);
  for (const name of COPIED_ASSETS) {
    const src = path.join(assetsDir, name);
    if (!fs.existsSync(src)) {
      throw new Error(`docmd-plugin-rsigma: missing asset ${src}`);
    }
    writeIfChanged(path.join(destDir, name), relinkToSiteBase(fs.readFileSync(src)));
  }

  for (const stale of STALE_BRAND_FILES) {
    const stalePath = path.join(destDir, stale);
    if (fs.existsSync(stalePath)) {
      fs.unlinkSync(stalePath);
    }
  }
}

/**
 * Generate brand images from the canonical theme-aware logo SVG at the repo
 * root into `{docsRoot}/assets/images/`. Keeps a single source of truth at the
 * repo root without git symlinks (which break on many Windows clones and are
 * unreliable on static hosts).
 *
 * @param {string} repoRoot
 * @param {string} docsRoot
 */
async function syncBrandAssets(repoRoot, docsRoot) {
  const logoSvg = path.join(repoRoot, "assets", "rsigma-logo.svg");
  if (!fs.existsSync(logoSvg)) {
    throw new Error(`docmd-plugin-rsigma: missing brand asset ${logoSvg}`);
  }
  await writeBrandImages(path.join(docsRoot, "assets", "images"), logoSvg);
}

/**
 * Read the `viewBox` of each copied diagram so its `<object>` embed can carry
 * the matching aspect ratio.
 *
 * @param {string} assetsDir
 * @returns {Map<string, string>} file name to a CSS `aspect-ratio` value
 */
function diagramAspectRatios(assetsDir) {
  const ratios = new Map();
  for (const name of COPIED_ASSETS) {
    const svg = fs.readFileSync(path.join(assetsDir, name), "utf8");
    const viewBox = svg.match(/viewBox="0 0 ([\d.]+) ([\d.]+)"/);
    if (!viewBox) {
      throw new Error(`docmd-plugin-rsigma: ${name} has no "0 0 W H" viewBox`);
    }
    ratios.set(name, `${viewBox[1]} / ${viewBox[2]}`);
  }
  return ratios;
}

/**
 * Wrap images of the copied diagrams in an `<object>` so their links and
 * hover styles work; SVG loaded through `<img>` is inert. docmd escapes raw
 * HTML in Markdown, so the page keeps a plain image and the swap happens here.
 * The original `<img>` stays inside as the fallback content.
 *
 * @param {string} html
 * @param {Map<string, string>} ratios
 */
function embedInteractiveDiagrams(html, ratios) {
  return html.replace(
    /(?<!<object[^>]*>)<img src="([^"]*\/assets\/images\/([\w-]+\.svg))" alt="([^"]*)">/g,
    (img, src, name, alt) => {
      const ratio = ratios.get(name);
      if (!ratio) {
        return img;
      }
      return `<object class="diagram" data="${src}" type="image/svg+xml" aria-label="${alt}" style="aspect-ratio: ${ratio}">${img}</object>`;
    },
  );
}

/**
 * Recursively collect every .html file under a directory.
 *
 * @param {string} dir
 * @returns {string[]}
 */
function collectHtmlFiles(dir) {
  /** @type {string[]} */
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...collectHtmlFiles(full));
    } else if (entry.isFile() && entry.name.endsWith(".html")) {
      out.push(full);
    }
  }
  return out;
}

export default {
  plugin: {
    name: "docmd-plugin-rsigma",
    version: "1.0.0",
    capabilities: ["init", "build", "post-build"],
  },

  async onConfigResolved(config) {
    if (typeof config?.url === "string" && config.url) {
      siteUrl = config.url;
    }
    if (typeof config?.base === "string" && config.base) {
      siteBase = config.base;
    }
    const docsRoot = process.cwd();
    repoRoot = findRepoRoot(docsRoot);
    rsigmaVars = loadRsigmaVars(repoRoot);
    releases = loadReleases(repoRoot);
    await syncBrandAssets(repoRoot, docsRoot);
  },

  onBeforeParse(src, _frontmatter, filePath) {
    if (!repoRoot) {
      repoRoot = findRepoRoot(process.cwd());
    }
    if (!rsigmaVars) {
      rsigmaVars = loadRsigmaVars(repoRoot);
    }
    if (!releases) {
      releases = loadReleases(repoRoot);
    }
    let out = inlineIncludeMarkdown(src, filePath ?? repoRoot, repoRoot);
    out = substituteRsigmaMacros(out, rsigmaVars);
    out = expandVersionTags(out, filePath ?? "a page", releases);
    // Linkify `#123` issue/PR shorthand on the release-notes page (the inlined
    // CHANGELOG), replacing the old MkDocs magiclink behaviour.
    if (typeof filePath === "string" && /release-notes\.md$/.test(filePath)) {
      const repoUrl =
        /** @type {any} */ (rsigmaVars)?.rsigma?.repo_url ||
        "https://github.com/timescale/rsigma";
      out = linkifyIssueRefs(out, repoUrl);
    }
    return out;
  },

  // docmd emits page-relative asset/link URLs (e.g. `../../assets/...`) together
  // with a `<base href="{siteRoot}">` tag. The base tag re-roots those relative
  // URLs at the site root, which breaks deep pages when combined with how the
  // client resolves paths. The client JS reads `window.DOCMD_BASE`, not the tag,
  // so removing the tag lets relative URLs resolve against the real document URL.
  async onPostBuild(ctx) {
    const outputDir = ctx?.outputDir ?? path.join(process.cwd(), "site");
    const log = typeof ctx?.log === "function" ? ctx.log : () => {};
    const docsRoot = process.cwd();
    const root = repoRoot ?? findRepoRoot(docsRoot);
    const logoSvg = path.join(root, "assets", "rsigma-logo.svg");
    await writeBrandImages(path.join(outputDir, "assets", "images"), logoSvg);
    await writeBrandImages(path.join(docsRoot, "assets", "images"), logoSvg);
    const ratios = diagramAspectRatios(path.dirname(logoSvg));
    let stripped = 0;
    let titlesRendered = 0;
    for (const file of collectHtmlFiles(outputDir)) {
      const html = fs.readFileSync(file, "utf8");
      let next = html.replace(/[ \t]*<base\b[^>]*>\n?/i, "");
      if (next !== html) {
        stripped += 1;
      }
      next = injectAnalyticsConsentMode(next);
      next = embedInteractiveDiagrams(next, ratios);
      const withTitles = renderMarkdownTitles(next);
      if (withTitles !== next) {
        titlesRendered += 1;
        next = withTitles;
      }
      if (next !== html) {
        fs.writeFileSync(file, next);
      }
    }
    const notesHtml = path.join(outputDir, "release-notes", "index.html");
    if (emittedReleaseAnchors.size > 0 && fs.existsSync(notesHtml)) {
      const notes = fs.readFileSync(notesHtml, "utf8");
      const broken = [];
      for (const file of collectHtmlFiles(outputDir)) {
        const html = fs.readFileSync(file, "utf8");
        for (const m of html.matchAll(/<a href="([^"]*)" class="docmd-tag-link"/g)) {
          const [target, anchor = ""] = m[1].split("#");
          const resolved = path.resolve(path.dirname(file), target, "index.html");
          if (resolved !== notesHtml || !notes.includes(`id="${anchor}"`)) {
            broken.push(`${path.relative(outputDir, file)} -> ${m[1]}`);
          }
        }
      }
      if (broken.length > 0) {
        throw new Error(
          `docmd-plugin-rsigma: version tags do not resolve to a release-notes heading:\n  ${broken.join("\n  ")}`,
        );
      }
    }
    log(
      `docmd-plugin-rsigma: stripped <base> tag from ${stripped} pages, rendered Markdown in ${titlesRendered} page titles, checked ${emittedReleaseAnchors.size} version-tag anchors`,
    );
  },
};
