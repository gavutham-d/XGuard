/**
 * Utility functions for XGuard extension.
 */

export function getRiskColor(level) {
  switch ((level || "").toLowerCase()) {
    case "critical":
      return "#EF4444";
    case "high":
      return "#F97316";
    case "medium":
      return "#F59E0B";
    case "low":
      return "#10B981";
    default:
      return "#64748B";
  }
}

export function getRiskBadgeClass(level) {
  switch ((level || "").toLowerCase()) {
    case "critical":
      return "badge-critical";
    case "high":
      return "badge-high";
    case "medium":
      return "badge-medium";
    case "low":
      return "badge-low";
    default:
      return "badge-unknown";
  }
}

export function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

export function formatTimestamp(isoStr) {
  if (!isoStr) return "Just now";
  try {
    const d = new Date(isoStr);
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  } catch (e) {
    return isoStr;
  }
}

export function formatDateFull(isoStr) {
  if (!isoStr) return "";
  try {
    const d = new Date(isoStr);
    return d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
  } catch (e) {
    return isoStr;
  }
}

export function truncateUrl(url, maxLen = 45) {
  if (!url) return "";
  if (url.length <= maxLen) return url;
  try {
    const parsed = new URL(url);
    const domain = parsed.hostname;
    const path = parsed.pathname;
    if (domain.length + path.length <= maxLen) return domain + path;
    return domain + "/..." + path.slice(-12);
  } catch (e) {
    return url.slice(0, maxLen - 3) + "...";
  }
}
