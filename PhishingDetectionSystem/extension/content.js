// content.js
console.log("PhisHawk Content Script Loaded");

// Listen for messages from the popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "extractEmail") {
    const emailData = extractEmailData();
    sendResponse(emailData);
  }
});

function extractEmailData() {
  // Selectors for Gmail (these might need updates if Gmail changes UI)
  
  // 1. Check if an email is actually open.
  // The subject line in an open email usually has the class 'hP'
  const subjectElement = document.querySelector("h2.hP");
  
  if (!subjectElement) {
      // If we can't find the subject header, we are likely in the Inbox/List view.
      return { error: "not_in_email" };
  }

  const subject = subjectElement.innerText;

  // Sender
  // We try to find the expanded email view's sender name/email
  let senderElement = document.querySelector("span.gD"); // Default sender class in open email
  let sender = senderElement ? senderElement.innerText + " <" + senderElement.getAttribute("email") + ">" : "Unknown Sender";

  // Body
  // We look for the main email body container. 
  // .a3s.aiL is a common class for the message body in Gmail
  let bodyElements = document.querySelectorAll(".a3s.aiL");
  let body = "";
  
  if (bodyElements.length > 0) {
      // Get the last one (most recent in thread usually) or combine them
      body = bodyElements[bodyElements.length - 1].innerText; 
  } else {
      // Fallback to body only if strictly necessary, but preferably fail if we can't find content
      return { error: "no_content_found" };
  }

  return {
    subject: subject,
    sender: sender,
    body: body,
    url: window.location.href
  };
}
