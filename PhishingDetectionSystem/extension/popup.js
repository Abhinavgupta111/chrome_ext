// popup.js

document.getElementById("analyze-btn").addEventListener("click", async () => {
    const statusDiv = document.getElementById("status");
    statusDiv.textContent = "Analyzing... please wait.";
    statusDiv.className = "loading";
  
    try {
      // Get active tab
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  
      // Send message to content script
      chrome.tabs.sendMessage(tab.id, { action: "extractEmail" }, async (response) => {
        if (chrome.runtime.lastError) {
          statusDiv.textContent = "Error: Please refresh the page and try again. Make sure you are on a Gmail page.";
          return;
        }
  
        if (!response) {
          statusDiv.textContent = "Error: Could not extract email data.";
          return;
        }

        if (response.error === "not_in_email") {
            statusDiv.innerHTML = "⚠️ <strong>Please open an email</strong><br>You are currently in the Inbox/List view.";
            return;
        }
        
        if (response.error === "no_content_found") {
             statusDiv.textContent = "Error: Could not extract email content.";
             return;
        }
  
        // Send data to local backend
        try {
          const apiResponse = await fetch("http://localhost:5000/analyze_text", {
             method: "POST",
             headers: {
               "Content-Type": "application/json"
             },
             body: JSON.stringify(response)
          });
  
          if (!apiResponse.ok) {
            throw new Error(`Server Error: ${apiResponse.statusText}`);
          }
  
          const result = await apiResponse.json();
          // Pass the extracted subject to the display function
          displayResults(result, response.subject);
  
        } catch (err) {
            console.error(err);
            statusDiv.textContent = "Error connecting to backend. Is main.py running?";
        }
      });
    } catch (err) {
        console.error(err);
        statusDiv.textContent = "Unexpected error occurred.";
    }
  });
  
  document.getElementById("back-btn").addEventListener("click", () => {
    document.getElementById("result-view").classList.add("hidden");
    document.getElementById("main-view").classList.remove("hidden");
    document.getElementById("status").textContent = "";
  });
  
  function displayResults(data, subject) {
    const mainView = document.getElementById("main-view");
    const resultView = document.getElementById("result-view");
    const verdictBanner = document.getElementById("verdict-banner");
    const riskLevel = document.getElementById("risk-level");
    const scoreDisplay = document.getElementById("score-display");
    const triggersList = document.getElementById("triggers-list");
    const subjectDisplay = document.getElementById("analyzed-subject");
  
    // Parse response
    // Expecting: { "status": "success", "data": { "score": ..., "verdict": ..., "risk_level": ..., "triggers": [] } }
    
    // Check if we received the expected structure
    const analysis = data.data ? data.data : data; 
  
    mainView.classList.add("hidden");
    resultView.classList.remove("hidden");
  
    riskLevel.textContent = analysis.verdict || "UNKNOWN";
    
    // Ensure score is an integer
    const scoreInt = Math.round(analysis.score);
    scoreDisplay.textContent = `Risk Score: ${scoreInt}/100`;

    // Display Subject
    subjectDisplay.textContent = subject || "Unknown Subject";
  
    // Style based on risk
    verdictBanner.className = "verdict-banner"; // reset
    if (analysis.risk_level === "HIGH" || analysis.verdict === "PHISHING") {
        verdictBanner.classList.add("high-risk");
    } else if (analysis.risk_level === "MEDIUM" || analysis.verdict === "SUSPICIOUS") {
        verdictBanner.classList.add("medium-risk");
    } else {
        verdictBanner.classList.add("low-risk");
    }
  
    // Triggers
    triggersList.innerHTML = "";
    if (analysis.triggers && analysis.triggers.length > 0) {
        analysis.triggers.forEach(trigger => {
            const li = document.createElement("li");
            li.textContent = trigger;
            triggersList.appendChild(li);
        });
    } else {
        const li = document.createElement("li");
        li.textContent = "No specific threats detected.";
        triggersList.appendChild(li);
    }
  }


