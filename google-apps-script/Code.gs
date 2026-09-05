/**
 * UK IAM JOB APPLICATION ARCHIVE
 * Google Apps Script backend
 *
 * Phase 1:
 * - Creates Google Sheet structure
 * - Creates Google Drive archive folder
 * - Receives job/application data from Python
 * - Fetches and archives complete job pages
 * - Writes structured data to Google Sheets
 */

const CONFIG = {
  ARCHIVE_FOLDER_NAME: "UK IAM Job Description Archive",
  SECRET_TOKEN: "IAMJOBSEARCHAUGUST2026"
};


/* ============================================================
   1. CREATE / REPAIR SHEET STRUCTURE
   ============================================================ */

function setupJobApplicationDatabase() {

  const ss = SpreadsheetApp.getActiveSpreadsheet();

  const sheets = {
    "Applications": [
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
    ],

    "Job Descriptions": [
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
    ],

    "Recruiters": [
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
    ],

    "Interviews": [
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
    ],

    "Dashboard": [
      "Metric",
      "Value"
    ]
  };

  Object.keys(sheets).forEach(function(sheetName) {

    let sheet = ss.getSheetByName(sheetName);

    if (!sheet) {
      sheet = ss.insertSheet(sheetName);
    }

    sheet.clear();

    const headers = sheets[sheetName];

    sheet
      .getRange(1, 1, 1, headers.length)
      .setValues([headers]);

    sheet
      .getRange(1, 1, 1, headers.length)
      .setFontWeight("bold");

    sheet.setFrozenRows(1);

    sheet.autoResizeColumns(
      1,
      headers.length
    );
  });

  createArchiveFolder();

  SpreadsheetApp.getUi().alert(
    "UK IAM Job Application database created successfully."
  );
}


/* ============================================================
   2. CREATE GOOGLE DRIVE ARCHIVE FOLDER
   ============================================================ */

function createArchiveFolder() {

  const folders = DriveApp.getFoldersByName(
    CONFIG.ARCHIVE_FOLDER_NAME
  );

  if (folders.hasNext()) {
    return folders.next().getId();
  }

  const folder = DriveApp.createFolder(
    CONFIG.ARCHIVE_FOLDER_NAME
  );

  return folder.getId();
}


/* ============================================================
   3. GET ARCHIVE FOLDER
   ============================================================ */

function getArchiveFolder() {

  const folders = DriveApp.getFoldersByName(
    CONFIG.ARCHIVE_FOLDER_NAME
  );

  if (folders.hasNext()) {
    return folders.next();
  }

  return DriveApp.createFolder(
    CONFIG.ARCHIVE_FOLDER_NAME
  );
}


/* ============================================================
   4. NORMALISE URL
   ============================================================ */

function canonicalUrl(url) {

  if (!url) {
    return "";
  }

  try {

    const parsed = new URL(url);

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
      .replace(/\/$/, "")
      .toLowerCase();
  }
}


/* ============================================================
   5. CHECK WHETHER URL ALREADY EXISTS
   ============================================================ */

function applicationExists(url) {

  const sheet =
    SpreadsheetApp
      .getActiveSpreadsheet()
      .getSheetByName("Job Descriptions");

  if (!sheet) {
    return false;
  }

  const lastRow = sheet.getLastRow();

  if (lastRow < 2) {
    return false;
  }

  const urls = sheet
    .getRange(
      2,
      6,
      lastRow - 1,
      1
    )
    .getValues();

  const target = canonicalUrl(url);

  return urls.some(function(row) {

    return canonicalUrl(
      row[0]
    ) === target;

  });
}


/* ============================================================
   6. ARCHIVE JOB PAGE
   ============================================================ */

function archiveJobPage(data) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();

  if (!ss) {
    throw new Error("Google Spreadsheet could not be found.");
  }

  // Get the required sheets explicitly.
  let jobSheet = ss.getSheetByName("Job Descriptions");
  let applicationSheet = ss.getSheetByName("Applications");

  // Create them if they don't exist.
  if (!jobSheet) {
    jobSheet = ss.insertSheet("Job Descriptions");

    jobSheet.appendRow([
      "Application ID",
      "Company",
      "Job Title",
      "Job Reference",
      "Original URL",
      "Canonical URL",
      "Capture Date",
      "HTTP Status",
      "Page Size",
      "Employment Type",
      "Location",
      "Working Arrangement",
      "Salary",
      "Status",
      "Matched Keywords",
      "Archive HTML",
      "Archive Text"
    ]);
  }

  if (!applicationSheet) {
    applicationSheet = ss.insertSheet("Applications");

    applicationSheet.appendRow([
      "Application ID",
      "Company",
      "Job Title",
      "Job Reference",
      "Original URL",
      "Canonical URL",
      "Application Date",
      "Status",
      "Notes"
    ]);
  }

  if (!data || !data.url) {
    throw new Error("No job URL supplied.");
  }

  const originalUrl = String(data.url);
  const canonical = canonicalUrl(originalUrl);

  // Prevent duplicate archives.
  if (applicationExists(canonical)) {
    return {
      success: true,
      duplicate: true,
      message: "Job URL already archived",
      canonicalUrl: canonical
    };
  }

  // Fetch the job page.
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
  } catch (err) {
    throw new Error(
      "Unable to fetch job page: " + err.message
    );
  }

  const httpStatus = response.getResponseCode();
  const html = response.getContentText();

  if (!html) {
    throw new Error("Job page returned no content.");
  }

  // Convert HTML to readable text.
  const readableText = html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/\s+/g, " ")
    .trim();

  const applicationId = createApplicationId();
  const captureDate = new Date();

  const company = data.company || "";
  const jobTitle = data.title || data.jobTitle || "";
  const jobReference = data.job_reference || data.jobReference || "";
  const employmentType = data.employment_type || data.employmentType || "";
  const location = data.location || "";
  const workingArrangement =
    data.working_arrangement || data.workingArrangement || "";
  const salary = data.salary || "";
  const status = data.status || "Discovered";
  const matchedKeywords =
    data.matched_keywords ||
    data.matchedKeywords ||
    "";

  // Create safe filename.
  const filename = sanitiseFilename(
    company + " - " + jobTitle + " - " + jobReference
  );

  // Get/create Drive archive folder.
  const folder = getArchiveFolder();

  // Save complete HTML.
  const htmlFile = folder.createFile(
    filename + ".html",
    html,
    MimeType.HTML
  );

  // Save readable text.
  const textFile = folder.createFile(
    filename + ".txt",
    readableText,
    MimeType.PLAIN_TEXT
  );

  // Store archive links.
  const htmlLink = htmlFile.getUrl();
  const textLink = textFile.getUrl();

  // Write to Job Descriptions.
  jobSheet.appendRow([
    applicationId,
    company,
    jobTitle,
    jobReference,
    originalUrl,
    canonical,
    captureDate,
    httpStatus,
    html.length,
    employmentType,
    location,
    workingArrangement,
    salary,
    status,
    matchedKeywords,
    htmlLink,
    textLink
  ]);

  // Write to Applications.
  applicationSheet.appendRow([
    applicationId,
    company,
    jobTitle,
    jobReference,
    originalUrl,
    canonical,
    captureDate,
    status,
    "Automatically discovered and archived."
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

function createApplicationId() {

  const sheet =
    SpreadsheetApp
      .getActiveSpreadsheet()
      .getSheetByName(
        "Applications"
      );

  const lastRow =
    sheet.getLastRow();

  let nextNumber =
    Math.max(
      1,
      lastRow
    );

  return (
    "APP-" +
    String(nextNumber)
      .padStart(4, "0")
  );
}


/* ============================================================
   8. CLEAN FILENAMES
   ============================================================ */

function sanitiseFilename(value) {

  return String(value)
    .replace(/[\\/:*?"<>|]/g, "")
    .replace(/\s+/g, " ")
    .trim()
    .substring(0, 100);
}


/* ============================================================
   9. WEB APP POST ENDPOINT
   ============================================================ */

function doPost(e) {

  try {

    if (!e || !e.postData) {

      return jsonResponse({
        success: false,
        error: "No POST data received."
      });
    }


    const payload =
      JSON.parse(
        e.postData.contents
      );


    /*
     * Security token.
     */

    if (
      payload.token !==
      CONFIG.SECRET_TOKEN
    ) {

      return jsonResponse({
        success: false,
        error: "Invalid token."
      });
    }


    const result =
      archiveJobPage(payload);


    return jsonResponse(
      result
    );

  } catch (error) {

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
    .createTextOutput(
      JSON.stringify(data)
    )
    .setMimeType(
      ContentService.MimeType.JSON
    );
}


/* ============================================================
   11. TEST SSE JOB
   ============================================================ */

function testSSEJob() {

  const testData = {

    token:
      CONFIG.SECRET_TOKEN,

    application_id:
      "APP-0001",

    date_applied:
      "2026-08-22",

    company:
      "SSE",

    title:
      "Product Owner – Identity " +
      "(Identity Governance & Administration)",

    job_reference:
      "559224",

    url:
      "https://careers.sse.com/jobs/" +
      "product-owner-identity-identity-governance-" +
      "administration-portsmouth-united-kingdom-" +
      "reading-berkshire-berkshire",

    source:
      "SSE Careers",

    salary:
      "£59,800–£89,800 + bonus",

    location:
      "Reading / Havant",

    working_arrangement:
      "Hybrid",

    employment_type:
      "Permanent",

    status:
      "Applied",

    matched_keywords:
      "Identity, Identity Governance, IGA, SailPoint"

  };


  const result =
    archiveJobPage(
      testData
    );


  Logger.log(
    JSON.stringify(
      result,
      null,
      2
    )
  );
}
