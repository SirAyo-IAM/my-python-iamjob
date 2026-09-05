/**
 * UK IAM JOB APPLICATION ARCHIVE
 * Google Apps Script backend
 *
 * Responsibilities:
 * - Receives job/application data from Python
 * - Fetches and archives complete job pages in Google Drive
 * - Writes structured records to Google Sheets
 * - Prevents duplicate archives by canonical URL
 *
 * Security:
 * - The webhook secret is stored in Apps Script Script Properties as
 *   ARCHIVE_SECRET_TOKEN. Never commit the secret to source control.
 */

const CONFIG = {
  ARCHIVE_FOLDER_ID: "1l2vXY9cmE7C-tQJ10aLCkSRCrcCSozI7",
  ARCHIVE_FOLDER_NAME: "UK IAM Job Description Archive",
  SECRET_PROPERTY_NAME: "ARCHIVE_SECRET_TOKEN"
};

const APPLICATION_HEADERS = [
  "Application ID",
  "Date Applied",
  "Company",
  "Job Title",
  "Job Reference",
  "Job URL",
  "Source",
  "Salary Min",
  "Salary Max",
  "Salary Text",
  "Employment Type",
  "Location",
  "Working Arrangement",
  "Status",
  "CV Used",
  "Matched Keywords",
  "Job Description Archive",
  "Match Score",
  "Outcome",
  "Notes",
  "Created At",
  "Last Updated"
];

const JOB_DESCRIPTION_HEADERS = [
  "Application ID",
  "Company",
  "Job Title",
  "Job Reference",
  "Original URL",
  "Canonical URL",
  "Capture Date",
  "HTTP Status",
  "Page Status",
  "Archive HTML",
  "Archive Text",
  "Full Job Description",
  "Responsibilities",
  "Requirements",
  "Technologies",
  "Certifications",
  "Salary",
  "Location",
  "Working Arrangement",
  "Source",
  "Matched Keywords"
];

const RECRUITER_HEADERS = [
  "Application ID",
  "Recruiter Name",
  "Company",
  "Recruiter Type",
  "Email",
  "Phone",
  "LinkedIn",
  "First Contact",
  "Last Contact",
  "Notes"
];

const INTERVIEW_HEADERS = [
  "Application ID",
  "Interview Stage",
  "Interview Date",
  "Interview Type",
  "Interviewers",
  "Questions",
  "Preparation",
  "Feedback",
  "Result",
  "Notes"
];

const DASHBOARD_HEADERS = ["Metric", "Value"];


/* ============================================================
   1. SAFE DATABASE SETUP / REPAIR
   ============================================================ */

function setupJobApplicationDatabase() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();

  if (!ss) {
    throw new Error("Google Spreadsheet could not be found.");
  }

  ensureSheet(ss, "Applications", APPLICATION_HEADERS);
  ensureSheet(ss, "Job Descriptions", JOB_DESCRIPTION_HEADERS);
  ensureSheet(ss, "Recruiters", RECRUITER_HEADERS);
  ensureSheet(ss, "Interviews", INTERVIEW_HEADERS);
  ensureSheet(ss, "Dashboard", DASHBOARD_HEADERS);
  getArchiveFolder();

  SpreadsheetApp.getUi().alert(
    "UK IAM Job Application database checked successfully. Existing data was preserved."
  );
}

function ensureSheet(ss, sheetName, headers) {
  let sheet = ss.getSheetByName(sheetName);

  if (!sheet) {
    sheet = ss.insertSheet(sheetName);
  }

  // Never clear an existing sheet. Only initialise headers when the sheet is empty.
  if (sheet.getLastRow() === 0) {
    sheet.getRange(1, 1, 1, headers.length).setValues([headers]);
    sheet.getRange(1, 1, 1, headers.length).setFontWeight("bold");
    sheet.setFrozenRows(1);
    sheet.autoResizeColumns(1, headers.length);
  }

  return sheet;
}


/* ============================================================
   2. SECURITY
   ============================================================ */

function getArchiveSecretToken() {
  const token = PropertiesService
    .getScriptProperties()
    .getProperty(CONFIG.SECRET_PROPERTY_NAME);

  if (!token) {
    throw new Error(
      "Missing Script Property: " + CONFIG.SECRET_PROPERTY_NAME
    );
  }

  return token;
}


/* ============================================================
   3. GOOGLE DRIVE ARCHIVE FOLDER
   ============================================================ */

function getArchiveFolder() {
  // Use the known folder ID so a duplicate folder with the same name cannot be selected.
  if (CONFIG.ARCHIVE_FOLDER_ID) {
    try {
      return DriveApp.getFolderById(CONFIG.ARCHIVE_FOLDER_ID);
    } catch (error) {
      throw new Error(
        "Configured archive folder is not accessible: " + error.message
      );
    }
  }

  const folders = DriveApp.getFoldersByName(CONFIG.ARCHIVE_FOLDER_NAME);

  if (folders.hasNext()) {
    return folders.next();
  }

  return DriveApp.createFolder(CONFIG.ARCHIVE_FOLDER_NAME);
}


/* ============================================================
   4. NORMALISE URL
   ============================================================ */

function canonicalUrl(url) {
  if (!url) {
    return "";
  }

  try {
    const parsed = new URL(String(url).trim());

    return (
      parsed.protocol +
      "//" +
      parsed.hostname +
      parsed.pathname
    )
      .replace(/\/$/, "")
      .toLowerCase();
  } catch (error) {
    return String(url)
      .trim()
      .split("?")[0]
      .split("#")[0]
      .replace(/\/$/, "")
      .toLowerCase();
  }
}


/* ============================================================
   5. DUPLICATE CHECK
   ============================================================ */

function applicationExists(url) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss && ss.getSheetByName("Job Descriptions");

  if (!sheet || sheet.getLastRow() < 2) {
    return false;
  }

  const headers = sheet
    .getRange(1, 1, 1, sheet.getLastColumn())
    .getValues()[0];

  const canonicalColumn = headers.indexOf("Canonical URL") + 1;

  if (canonicalColumn < 1) {
    throw new Error("Job Descriptions sheet is missing the Canonical URL column.");
  }

  const target = canonicalUrl(url);
  const values = sheet
    .getRange(2, canonicalColumn, sheet.getLastRow() - 1, 1)
    .getValues();

  return values.some(function(row) {
    return canonicalUrl(row[0]) === target;
  });
}


/* ============================================================
   6. ARCHIVE JOB PAGE
   ============================================================ */

function archiveJobPage(data) {
  if (!data || !data.url) {
    throw new Error("No job URL supplied.");
  }

  const ss = SpreadsheetApp.getActiveSpreadsheet();

  if (!ss) {
    throw new Error("Google Spreadsheet could not be found.");
  }

  const applicationSheet = ensureSheet(
    ss,
    "Applications",
    APPLICATION_HEADERS
  );

  const jobSheet = ensureSheet(
    ss,
    "Job Descriptions",
    JOB_DESCRIPTION_HEADERS
  );

  const originalUrl = String(data.url).trim();
  const canonical = canonicalUrl(originalUrl);

  if (applicationExists(canonical)) {
    return {
      success: true,
      duplicate: true,
      message: "Job URL already archived",
      canonicalUrl: canonical
    };
  }

  let response;

  try {
    response = UrlFetchApp.fetch(originalUrl, {
      muteHttpExceptions: true,
      followRedirects: true,
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/151 Safari/537.36"
      }
    });
  } catch (error) {
    throw new Error("Unable to fetch job page: " + error.message);
  }

  const httpStatus = response.getResponseCode();
  const html = response.getContentText();

  if (httpStatus >= 400) {
    throw new Error("Job page returned HTTP " + httpStatus + ".");
  }

  if (!html || !html.trim()) {
    throw new Error("Job page returned no content.");
  }

  const readableText = html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/\s+/g, " ")
    .trim();

  const captureDate = new Date();
  const applicationId = createApplicationId(applicationSheet);

  const company = data.company || "";
  const jobTitle = data.title || data.jobTitle || "";
  const jobReference = data.job_reference || data.jobReference || "";
  const employmentType = data.employment_type || data.employmentType || "";
  const location = data.location || "";
  const workingArrangement =
    data.working_arrangement || data.workingArrangement || "";
  const salary = data.salary || data.salary_text || "";
  const salaryMin = data.salary_min || "";
  const salaryMax = data.salary_max || "";
  const source = data.source || "";
  const status = data.status || "Discovered";
  const dateApplied = data.date_applied || data.dateApplied || "";
  const cvUsed = data.cv_used || data.cvUsed || "";
  const matchScore = data.match_score || data.matchScore || "";
  const matchedKeywords = normaliseListValue(
    data.matched_keywords || data.matchedKeywords || ""
  );

  const filename = sanitiseFilename(
    [company, jobTitle, jobReference].filter(Boolean).join(" - ") || applicationId
  );

  const folder = getArchiveFolder();

  const htmlFile = folder.createFile(
    filename + ".html",
    html,
    MimeType.HTML
  );

  const textFile = folder.createFile(
    filename + ".txt",
    readableText,
    MimeType.PLAIN_TEXT
  );

  const htmlLink = htmlFile.getUrl();
  const textLink = textFile.getUrl();

  jobSheet.appendRow([
    applicationId,
    company,
    jobTitle,
    jobReference,
    originalUrl,
    canonical,
    captureDate,
    httpStatus,
    "Captured",
    htmlLink,
    textLink,
    readableText,
    normaliseListValue(data.responsibilities || ""),
    normaliseListValue(data.requirements || ""),
    normaliseListValue(data.technologies || ""),
    normaliseListValue(data.certifications || ""),
    salary,
    location,
    workingArrangement,
    source,
    matchedKeywords
  ]);

  applicationSheet.appendRow([
    applicationId,
    dateApplied,
    company,
    jobTitle,
    jobReference,
    originalUrl,
    source,
    salaryMin,
    salaryMax,
    salary,
    employmentType,
    location,
    workingArrangement,
    status,
    cvUsed,
    matchedKeywords,
    textLink,
    matchScore,
    data.outcome || "",
    data.notes || "Automatically discovered and archived.",
    captureDate,
    captureDate
  ]);

  return {
    success: true,
    duplicate: false,
    applicationId: applicationId,
    company: company,
    title: jobTitle,
    url: originalUrl,
    canonicalUrl: canonical,
    httpStatus: httpStatus,
    htmlArchive: htmlLink,
    textArchive: textLink
  };
}


/* ============================================================
   7. CREATE APPLICATION ID
   ============================================================ */

function createApplicationId(applicationSheet) {
  const lock = LockService.getScriptLock();
  lock.waitLock(10000);

  try {
    const sheet = applicationSheet ||
      SpreadsheetApp.getActiveSpreadsheet().getSheetByName("Applications");

    if (!sheet) {
      return "APP-0001";
    }

    const lastRow = sheet.getLastRow();

    if (lastRow < 2) {
      return "APP-0001";
    }

    const ids = sheet
      .getRange(2, 1, lastRow - 1, 1)
      .getValues()
      .flat()
      .map(function(value) {
        const match = String(value).match(/^APP-(\d+)$/i);
        return match ? Number(match[1]) : 0;
      });

    const nextNumber = Math.max.apply(null, [0].concat(ids)) + 1;

    return "APP-" + String(nextNumber).padStart(4, "0");
  } finally {
    lock.releaseLock();
  }
}


/* ============================================================
   8. HELPERS
   ============================================================ */

function sanitiseFilename(value) {
  return String(value)
    .replace(/[\\/:*?"<>|]/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .substring(0, 100);
}

function normaliseListValue(value) {
  if (Array.isArray(value)) {
    return value.join(", ");
  }

  return value == null ? "" : String(value);
}


/* ============================================================
   9. WEB APP ENDPOINTS
   ============================================================ */

function doGet() {
  return jsonResponse({
    success: true,
    service: "UK IAM Job Application Archive",
    status: "ready"
  });
}

function doPost(e) {
  try {
    if (!e || !e.postData || !e.postData.contents) {
      return jsonResponse({
        success: false,
        error: "No POST data received."
      });
    }

    const payload = JSON.parse(e.postData.contents);
    const expectedToken = getArchiveSecretToken();

    if (!payload.token || payload.token !== expectedToken) {
      return jsonResponse({
        success: false,
        error: "Invalid token."
      });
    }

    delete payload.token;

    return jsonResponse(archiveJobPage(payload));
  } catch (error) {
    console.error(error);

    return jsonResponse({
      success: false,
      error: error.message
    });
  }
}


/* ============================================================
   10. JSON RESPONSE
   ============================================================ */

function jsonResponse(data) {
  return ContentService
    .createTextOutput(JSON.stringify(data))
    .setMimeType(ContentService.MimeType.JSON);
}


/* ============================================================
   11. MANUAL ARCHIVE TEST
   ============================================================ */

function testSSEJob() {
  const testData = {
    application_id: "APP-0001",
    date_applied: "2026-08-22",
    company: "SSE",
    title: "Product Owner – Identity (Identity Governance & Administration)",
    job_reference: "559224",
    url:
      "https://careers.sse.com/jobs/" +
      "product-owner-identity-identity-governance-" +
      "administration-portsmouth-united-kingdom-" +
      "reading-berkshire-berkshire",
    source: "SSE Careers",
    salary: "£59,800–£89,800 + bonus",
    location: "Reading / Havant",
    working_arrangement: "Hybrid",
    employment_type: "Permanent",
    status: "Applied",
    matched_keywords: "Identity, Identity Governance, IGA, SailPoint"
  };

  const result = archiveJobPage(testData);
  Logger.log(JSON.stringify(result, null, 2));
}
