/**
 * Welcome / Onboarding Page Controller.
 */

document.addEventListener("DOMContentLoaded", () => {
  const btnLaunchSidebar = document.getElementById("btnLaunchSidebar");

  btnLaunchSidebar.addEventListener("click", () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tab = tabs[0];
      if (tab?.id && chrome.sidePanel && chrome.sidePanel.open) {
        chrome.sidePanel.open({ tabId: tab.id }).catch(() => {});
      }
    });
  });
});
