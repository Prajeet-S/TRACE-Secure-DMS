import { useEffect, useState } from "react";

const API = "http://127.0.0.1:8000";

const publicRoles = [
  "Police/Investigator",
  "Lawyer/Legal Officer",
  "Court Authority",
];

const navItems = [
  { id: "dashboard", label: "Dashboard", icon: "▦" },
  { id: "active-users", label: "Active Case Users", icon: "♙", adminOnly: true },
  { id: "cases", label: "Cases", icon: "◈" },
  { id: "documents", label: "Documents", icon: "▤" },
  { id: "search", label: "Search", icon: "⌕" },
  { id: "audit", label: "Audit Trail", icon: "◷" },
  { id: "security", label: "Security", icon: "◉" },
];

const roleAccents = {
  "Police/Investigator": {
    name: "Police",
    bg: "hover:bg-blue-500/15 hover:border-blue-400/40",
    text: "group-hover:text-blue-200",
    glow: "from-blue-400/30 via-cyan-300/10 to-transparent",
  },
  "Lawyer/Legal Officer": {
    name: "Lawyer",
    bg: "hover:bg-amber-500/15 hover:border-amber-300/40",
    text: "group-hover:text-amber-100",
    glow: "from-amber-300/30 via-orange-300/10 to-transparent",
  },
  "Court Authority": {
    name: "Court",
    bg: "hover:bg-emerald-500/15 hover:border-emerald-300/40",
    text: "group-hover:text-emerald-100",
    glow: "from-emerald-300/30 via-teal-300/10 to-transparent",
  },
};

function isAdmin(user) {
  return user?.role === "Administrator";
}

function visibleNavItems(user) {
  return navItems.filter((item) => !item.adminOnly || isAdmin(user));
}

function formatLocalDateTime(value) {
  if (!value) return "-";
  return new Date(value).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function App() {
  const storedToken = localStorage.getItem("sih_token") || "";
  const [page, setPage] = useState(storedToken ? "dashboard" : "home");
  const [selectedRole, setSelectedRole] = useState("");
  const [showLogin, setShowLogin] = useState(false);
  const [showSignup, setShowSignup] = useState(false);

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [signupUsername, setSignupUsername] = useState("");
  const [signupEmail, setSignupEmail] = useState("");
  const [signupPassword, setSignupPassword] = useState("");
  const [signupConfirmPassword, setSignupConfirmPassword] = useState("");
  const [signupRole, setSignupRole] = useState("");
  const [signupError, setSignupError] = useState("");
  const [signupLoading, setSignupLoading] = useState(false);

  const [token, setToken] = useState(storedToken);

  const [user, setUser] = useState(
    JSON.parse(localStorage.getItem("sih_user") || "null")
  );

  const [loginError, setLoginError] = useState("");
  const [loading, setLoading] = useState(false);
  const [otpStep, setOtpStep] = useState(false);
  const [otp, setOtp] = useState("");
  const [otpLoading, setOtpLoading] = useState(false);

  const [dashboard, setDashboard] = useState({
    role: user?.role || "",
    users: 0,
    cases: 0,
    documents: 0,
    audit_events: 0,
    open_security_alerts: 0,
    actions: [],
  });

  const [cases, setCases] = useState([]);
  const [documents, setDocuments] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [securityAlerts, setSecurityAlerts] = useState([]);
  const [alertsLoading, setAlertsLoading] = useState(false);
  const [activeCaseUsers, setActiveCaseUsers] = useState([]);
  const [activeUsersLoading, setActiveUsersLoading] = useState(false);

  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState([]);

  const [newCase, setNewCase] = useState({
    case_number: "",
    title: "",
    description: "",
    status: "Active",
  });

  const [showCaseForm, setShowCaseForm] = useState(false);

  const [uploadCaseId, setUploadCaseId] = useState("");
  const [documentType, setDocumentType] = useState("Evidence");
  const [selectedFile, setSelectedFile] = useState(null);
  const [uploadMessage, setUploadMessage] = useState("");
  const [uploading, setUploading] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState(null);
  const [deletePassword, setDeletePassword] = useState("");
  const [deleteLoading, setDeleteLoading] = useState(false);
  const [caseAction, setCaseAction] = useState(null);
  const [caseActionPassword, setCaseActionPassword] = useState("");
  const [caseActionLoading, setCaseActionLoading] = useState(false);
  const [showIntro, setShowIntro] = useState(true);


  useEffect(() => {
    if (token) {
      loadDashboard();
    }
  }, [token]);

  async function apiRequest(endpoint, options = {}) {
    const headers = {
      ...(options.headers || {}),
    };

    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }

    const response = await fetch(`${API}${endpoint}`, {
      ...options,
      headers,
    });

    const data = await response.json();

    if (!response.ok) {
      const detail =
        typeof data.detail === "object"
          ? data.detail?.message || JSON.stringify(data.detail)
          : data.detail;

      throw new Error(
        detail || data.error || "Something went wrong"
      );
    }

    return data;
  }

  async function handleLogin(e) {
    e.preventDefault();

    setLoading(true);
    setLoginError("");

    try {
      const response = await fetch(`${API}/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          email,
          password,
          role: selectedRole,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail || "Invalid email, password or role."
        );
      }

      if (data.requires_otp) {
        setOtpStep(true);
        setOtp("");
        setLoginError("");
        return;
      }

      // Backward-compatible fallback if the backend returns a token directly.
      if (data.access_token) {
        localStorage.setItem("sih_token", data.access_token);
        localStorage.setItem("sih_user", JSON.stringify(data.user));

        setToken(data.access_token);
        setUser(data.user);
        setShowLogin(false);
        setPage("dashboard");

        setEmail("");
        setPassword("");
      }
    } catch (error) {
      setLoginError(error.message);
    } finally {
      setLoading(false);
    }
  }

  async function handleSignup(e) {
    e.preventDefault();

    if (!signupRole) {
      setSignupError("Please select your role.");
      return;
    }
    if (signupPassword !== signupConfirmPassword) {
      setSignupError("Passwords do not match.");
      return;
    }

    setSignupLoading(true);
    setSignupError("");
    try {
      const response = await fetch(`${API}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: signupUsername,
          email: signupEmail,
          password: signupPassword,
          role: signupRole,
        }),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || "Unable to create account.");
      }

      setEmail(signupEmail.trim().toLowerCase());
      setPassword("");
      setSelectedRole(signupRole);
      setSignupUsername("");
      setSignupEmail("");
      setSignupPassword("");
      setSignupConfirmPassword("");
      setShowSignup(false);
      setShowLogin(true);
      setLoginError("Account created. Sign in to receive your OTP.");
    } catch (error) {
      setSignupError(error.message);
    } finally {
      setSignupLoading(false);
    }
  }

  async function handleVerifyOtp(e) {
    e.preventDefault();

    if (!otp || otp.length !== 6) {
      setLoginError("Please enter the 6-digit OTP.");
      return;
    }

    setOtpLoading(true);
    setLoginError("");

    try {
      const response = await fetch(`${API}/verify-otp`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          email: email,
          otp: otp,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        const detail =
          typeof data.detail === "object"
            ? data.detail?.message || JSON.stringify(data.detail)
            : data.detail;

        throw new Error(detail || "Invalid OTP.");
      }

      if (!data.access_token) {
        throw new Error("OTP verified, but no access token was returned.");
      }

      localStorage.setItem("sih_token", data.access_token);
      localStorage.setItem("sih_user", JSON.stringify(data.user));

      setToken(data.access_token);
      setUser(data.user);
      setShowLogin(false);
      setOtpStep(false);
      setPage("dashboard");

      setEmail("");
      setPassword("");
      setOtp("");
    } catch (error) {
      setLoginError(error.message || "OTP verification failed.");
    } finally {
      setOtpLoading(false);
    }
  }

  function logout() {
    localStorage.removeItem("sih_token");
    localStorage.removeItem("sih_user");

    setToken("");
    setUser(null);
    setPage("home");
  }

  async function loadDashboard() {
    try {
      const data = await apiRequest("/dashboard");
      console.log("TRACE dashboard data:", data);
      setDashboard({
        role: data.role || user?.role || "",
        users: Number(data.users ?? 0),
        cases: Number(data.cases ?? 0),
        documents: Number(data.documents ?? 0),
        audit_events: Number(data.audit_events ?? 0),
        open_security_alerts: Number(data.open_security_alerts ?? 0),
        actions: Array.isArray(data.actions) ? data.actions : [],
      });
    } catch (error) {
      console.error(error);
    }
  }

  async function loadCases() {
    try {
      const data = await apiRequest("/cases");
      setCases(data);
    } catch (error) {
      console.error(error);
    }
  }

  async function loadDocuments() {
    try {
      const data = await apiRequest("/documents");
      setDocuments(data);
    } catch (error) {
      console.error(error);
    }
  }

  async function loadAuditLogs() {
    try {
      const data = await apiRequest("/audit-logs");
      setAuditLogs(data);
    } catch (error) {
      console.error(error);
    }
  }

  async function loadSecurityAlerts() {
    setAlertsLoading(true);
    try {
      const data = await apiRequest("/security/alerts");
      setSecurityAlerts(Array.isArray(data) ? data : []);
    } catch (error) {
      console.error(error);
    } finally {
      setAlertsLoading(false);
    }
  }

  async function loadActiveCaseUsers() {
    setActiveUsersLoading(true);
    try {
      const data = await apiRequest("/admin/active-case-users");
      setActiveCaseUsers(Array.isArray(data) ? data : []);
    } catch (error) {
      console.error(error);
    } finally {
      setActiveUsersLoading(false);
    }
  }

  async function updateAlert(alertId, action) {
    try {
      const updatedAlert = await apiRequest(`/security/alerts/${alertId}`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ action }),
      });

      if (action === "dismiss") {
        setSecurityAlerts((items) => items.filter((item) => item.id !== alertId));
      } else {
        setSecurityAlerts((items) =>
          items.map((item) => (item.id === alertId ? updatedAlert : item))
        );
      }

      await loadDashboard();
    } catch (error) {
      alert(error.message);
    }
  }

  async function createCase(e) {
    e.preventDefault();

    try {
      await apiRequest("/cases", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(newCase),
      });

      setNewCase({
        case_number: "",
        title: "",
        description: "",
        status: "Active",
      });

      setShowCaseForm(false);

      await loadCases();
      await loadDashboard();

      alert("Case created successfully.");
    } catch (error) {
      alert(error.message);
    }
  }

  async function uploadDocument(e) {
    e.preventDefault();

    if (!uploadCaseId || !selectedFile) {
      setUploadMessage("Please select a case and a file.");
      return;
    }

    setUploading(true);
    setUploadMessage("");

    try {
      const formData = new FormData();

      formData.append("case_id", uploadCaseId);
      formData.append("document_type", documentType);
      formData.append("file", selectedFile);

      const response = await fetch(`${API}/documents/upload`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
        },
        body: formData,
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail?.message ||
            data.detail ||
            "Document upload failed."
        );
      }

      setUploadMessage("Uploaded successfully.");

      setSelectedFile(null);

      await loadDocuments();
      await loadDashboard();
    } catch (error) {
      setUploadMessage(error.message);
    } finally {
      setUploading(false);
    }
  }

  async function searchDocuments() {
    if (!searchQuery.trim()) return;

    try {
      const data = await apiRequest(
        `/documents/search?q=${encodeURIComponent(searchQuery)}`
      );

      setSearchResults(data.results);
    } catch (error) {
      alert(error.message);
    }
  }
  async function openDocument(documentId, filename) {
  try {
    const response = await fetch(
      `${API}/documents/${documentId}/file`,
      {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      }
    );

    if (!response.ok) {
      let message = "Unable to open document.";

      try {
        const data = await response.json();
        message = data.detail || message;
      } catch {
        // Response was not JSON
      }

      throw new Error(message);
    }

    const blob = await response.blob();

    const blobUrl = window.URL.createObjectURL(blob);

    const newWindow = window.open(
      blobUrl,
      "_blank",
      "noopener,noreferrer"
    );

    if (!newWindow) {
      const link = document.createElement("a");
      link.href = blobUrl;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.click();
    }

    setTimeout(() => {
      window.URL.revokeObjectURL(blobUrl);
    }, 60000);

  } catch (error) {
    alert(error.message || `Unable to open ${filename}.`);
  }
}

  async function verifyDocument(documentId) {
    try {
      const data = await apiRequest(
        `/documents/${documentId}/verify`
      );

      alert(
        `Integrity: ${data.integrity}\n\nStored hash:\n${data.stored_hash}\n\nCurrent hash:\n${data.current_hash}`
      );

      await loadAuditLogs();
    } catch (error) {
      alert(error.message);
    }
  }
  function requestDelete(type, id, name) {
  setDeletePassword("");
  setDeleteTarget({
    type,
    id,
    name
  });
}
function requestCaseAction(action, id, name) {
  setCaseActionPassword("");

  setCaseAction({
    action,
    id,
    name,
  });
}
async function confirmCaseAction() {
  if (!caseAction || !caseActionPassword) return;

  setCaseActionLoading(true);

  try {
    const endpoint =
      caseAction.action === "close"
        ? `/cases/${caseAction.id}/close`
        : `/cases/${caseAction.id}/reopen`;

    await apiRequest(endpoint, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        password: caseActionPassword,
      }),
    });

    const action = caseAction.action;

    setCaseAction(null);
    setCaseActionPassword("");

    await loadCases();
    await loadDocuments();
    await loadDashboard();
    await loadAuditLogs();

    alert(
      action === "close"
        ? "Case closed successfully."
        : "Case reopened successfully."
    );
  } catch (error) {
    alert(error.message);
  } finally {
    setCaseActionLoading(false);
  }
}
function requestCloseCase(caseId, caseNumber) {
  setDeletePassword("");

  setDeleteTarget({
    type: "close-case",
    id: caseId,
    name: caseNumber
  });
}
function requestReopenCase(caseId, caseNumber) {
  setDeletePassword("");

  setDeleteTarget({
    type: "reopen-case",
    id: caseId,
    name: caseNumber
  });
}
async function confirmDelete() {
  if (!deleteTarget || !deletePassword) return;

  setDeleteLoading(true);

  try {
    let endpoint;
    let method;

    if (deleteTarget.type === "document") {
      endpoint = `/documents/${deleteTarget.id}`;
      method = "DELETE";
    } else if (deleteTarget.type === "case") {
      endpoint = `/cases/${deleteTarget.id}`;
      method = "DELETE";
    } else if (deleteTarget.type === "close-case") {
      endpoint = `/cases/${deleteTarget.id}/close`;
      method = "PUT";
    } else if (deleteTarget.type === "reopen-case") {
      endpoint = `/cases/${deleteTarget.id}/reopen`;
      method = "PUT";
    }

    const data = await apiRequest(endpoint, {
      method,
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        password: deletePassword
      })
    });

    const actionType = deleteTarget.type;

    setDeleteTarget(null);
    setDeletePassword("");

    await loadCases();
    await loadDocuments();
    await loadDashboard();
    await loadAuditLogs();

    if (actionType === "document") {
      alert("Document deleted permanently.");
    } else if (actionType === "case") {
      alert("Case and its documents were permanently deleted.");
    } else if (actionType === "close-case") {
      alert("Case closed successfully. Its documents are now locked.");
    } else if (actionType === "reopen-case") {
      alert("Case reopened successfully. Its documents are accessible again.");
    }

  } catch (error) {
    alert(error.message);
  } finally {
    setDeleteLoading(false);
  }
}
async function closeCase(caseId, caseNumber, password) {
  try {
    await apiRequest(`/cases/${caseId}/close`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        password: password
      })
    });

    await loadCases();
    await loadDashboard();
    await loadAuditLogs();

    alert("Case closed successfully.");
  } catch (error) {
    alert(error.message);
  }
}

  function openDashboardPage(id) {
    setPage(id);

    if (id === "dashboard") {
      loadDashboard();
    }

    if (id === "cases") {
      loadCases();
    }

    if (id === "active-users") {
      loadActiveCaseUsers();
    }

    if (id === "documents") {
      loadCases();
      loadDocuments();
    }

    if (id === "search") {
    loadDocuments();
    }

    if (id === "audit") {
      loadAuditLogs();
    }

    if (id === "security") {
      loadSecurityAlerts();
      loadDashboard();
    }
  }

  if (!token) {
    return (
      <>
        {showIntro && <IntroSplash onFinish={() => setShowIntro(false)} />}

        <LandingPage
          selectedRole={selectedRole}
          setSelectedRole={setSelectedRole}
          onLogin={() => {
            setLoginError("");
            setShowLogin(true);
          }}
          onSignup={() => {
            setSignupError("");
            setShowSignup(true);
          }}
        />

        {showLogin && (
          <LoginModal
            role={selectedRole}
            setRole={setSelectedRole}
            email={email}
            setEmail={setEmail}
            password={password}
            setPassword={setPassword}
            error={loginError}
            loading={loading}
            otpStep={otpStep}
            otp={otp}
            setOtp={setOtp}
            otpLoading={otpLoading}
            onClose={() => {
              setShowLogin(false);
              setOtpStep(false);
              setOtp("");
              setLoginError("");
            }}
            onSubmit={otpStep ? handleVerifyOtp : handleLogin}
            onBackToLogin={() => {
              setOtpStep(false);
              setOtp("");
              setLoginError("");
            }}
          />
        )}

        {showSignup && (
          <SignupModal
            username={signupUsername}
            setUsername={setSignupUsername}
            email={signupEmail}
            setEmail={setSignupEmail}
            password={signupPassword}
            setPassword={setSignupPassword}
            confirmPassword={signupConfirmPassword}
            setConfirmPassword={setSignupConfirmPassword}
            role={signupRole}
            setRole={setSignupRole}
            error={signupError}
            loading={signupLoading}
            onClose={() => setShowSignup(false)}
            onSubmit={handleSignup}
            onLogin={() => {
              setShowSignup(false);
              setLoginError("");
              setShowLogin(true);
            }}
          />
        )}
      </>
    );
  }

  return (
  <>
    {showIntro && <IntroSplash onFinish={() => setShowIntro(false)} />}
    <DashboardLayout
      page={page}
      setPage={openDashboardPage}
      user={user}
      logout={logout}
    >
      {page === "dashboard" && (
        <DashboardHome
          user={user}
          stats={dashboard}
          cases={cases}
          loadCases={loadCases}
          onViewAlerts={() => openDashboardPage("security")}
        />
      )}

      {page === "cases" && (
        <CasesPage
          cases={cases}
          showForm={showCaseForm}
          setShowForm={setShowCaseForm}
          newCase={newCase}
          setNewCase={setNewCase}
          createCase={createCase}
          onDeleteCase={(caseId, caseNumber) =>
            requestDelete("case", caseId, caseNumber)
          }
          onCloseCase={(caseId, caseNumber) =>
            requestCloseCase(caseId, caseNumber)
          }
          onReopenCase={(caseId, caseNumber) =>
            requestReopenCase(caseId, caseNumber)
          }
        />
      )}

      {page === "active-users" && (
        <ActiveUsersPage
          users={activeCaseUsers}
          loading={activeUsersLoading}
          onRefresh={loadActiveCaseUsers}
        />
      )}

      {page === "documents" && (
        <DocumentsPage
          documents={documents}
          cases={cases}
          uploadCaseId={uploadCaseId}
          setUploadCaseId={setUploadCaseId}
          documentType={documentType}
          setDocumentType={setDocumentType}
          selectedFile={selectedFile}
          setSelectedFile={setSelectedFile}
          uploadDocument={uploadDocument}
          uploading={uploading}
          uploadMessage={uploadMessage}
          verifyDocument={verifyDocument}
          onDeleteDocument={(documentId, filename) =>
          requestDelete("document", documentId, filename)
        }
        />
      )}

      {page === "search" && (
        <SearchPage
          query={searchQuery}
          setQuery={setSearchQuery}
          search={searchDocuments}
          results={searchResults}
          documents={documents}
          openDocument={openDocument}
        />
      )}

      {page === "audit" && (
        <AuditPage logs={auditLogs} />
      )}

            {page === "security" && (
        <SecurityPage
          user={user}
          alerts={securityAlerts}
          loading={alertsLoading}
          onRefresh={loadSecurityAlerts}
          onUpdateAlert={updateAlert}
        />
      )}

      {deleteTarget && (
        <DeleteConfirmModal
          target={deleteTarget}
          password={deletePassword}
          setPassword={setDeletePassword}
          loading={deleteLoading}
          onCancel={() => {
            if (!deleteLoading) {
              setDeleteTarget(null);
              setDeletePassword("");
            }
          }}
          onConfirm={confirmDelete}
        />
      )}
      {caseAction && (
        <CaseActionModal
          action={caseAction.action}
          name={caseAction.name}
          password={caseActionPassword}
          setPassword={setCaseActionPassword}
          loading={caseActionLoading}
          onCancel={() => {
            if (!caseActionLoading) {
              setCaseAction(null);
              setCaseActionPassword("");
            }
          }}
          onConfirm={confirmCaseAction}
        />
      )}
    </DashboardLayout>
  </>
);
}
function DeleteConfirmModal({
  target,
  password,
  setPassword,
  loading,
  onCancel,
  onConfirm,
}) {
  const isDocument = target.type === "document";
  const isCase = target.type === "case";
  const isClose = target.type === "close-case";
  const isReopen = target.type === "reopen-case";

  let title = "Confirm Deletion";
  let description = "";
  let buttonText = "Confirm Delete";

  if (isDocument) {
    title = "Delete Document";
    description =
      "This will permanently delete the document from the system and Azure Blob Storage.";
    buttonText = "Delete Document";
  } else if (isCase) {
    title = "Delete Case";
    description =
      "This will permanently delete the case and its associated documents.";
    buttonText = "Delete Case";
  } else if (isClose) {
    title = "Close Case";
    description =
      "Closing this case will lock its documents. They cannot be opened, verified, uploaded to, or modified until the case is reopened.";
    buttonText = "Close Case";
  } else if (isReopen) {
    title = "Reopen Case";
    description =
      "Reopening this case will restore access to its documents.";
    buttonText = "Reopen Case";
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
      <div className="w-full max-w-md rounded-2xl border border-white/10 bg-ink-900 p-6 shadow-2xl">

        <h2 className="text-xl font-bold text-white">
          {title}
        </h2>

        <p className="mt-2 text-sm text-parchment-500">
          {description}
        </p>

        <p className="mt-4 text-sm text-parchment-500">
          Target:
        </p>

        <p className="mt-1 font-semibold text-white">
          {target.name}
        </p>

        <p className="mt-4 text-sm text-parchment-500">
          Enter your password to verify your identity.
        </p>

        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && password && !loading) {
              onConfirm();
            }
          }}
          placeholder="Enter your password"
          className="input mt-3 w-full"
          autoFocus
        />

        <div className="mt-5 flex justify-end gap-3">

          <button
            type="button"
            onClick={onCancel}
            disabled={loading}
            className="px-4 py-2 rounded-xl border border-white/10 text-parchment-400"
          >
            Cancel
          </button>

          <button
            type="button"
            onClick={onConfirm}
            disabled={!password || loading}
            className={`px-4 py-2 rounded-xl font-semibold text-white disabled:opacity-50 ${
              isClose
                ? "bg-amber-500"
                : isReopen
                ? "bg-cyan-500"
                : "bg-red-500"
            }`}
          >
            {loading ? "Verifying..." : buttonText}
          </button>

        </div>
      </div>
    </div>
  );
}

function CaseActionModal({
  action,
  name,
  password,
  setPassword,
  loading,
  onCancel,
  onConfirm,
}) {
  const isClosing = action === "close";

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
      <div className="w-full max-w-md rounded-2xl border border-white/10 bg-ink-900 p-6 shadow-2xl">

        <h2 className="text-xl font-bold text-white">
          {isClosing
            ? "Close Case"
            : "Reopen Case"}
        </h2>

        <p className="mt-2 text-sm text-parchment-500">
          {isClosing
            ? "You are about to close this case:"
            : "You are about to reopen this case:"}
        </p>

        <p className="mt-2 font-semibold text-white">
          {name}
        </p>

        <p className="mt-4 text-sm text-parchment-500">
          {isClosing
            ? "Files belonging to a closed case cannot be interacted with until the case is reopened."
            : "Enter your password to verify your identity and reopen this case."}
        </p>

        <input
          type="password"
          value={password}
          onChange={(e) =>
            setPassword(e.target.value)
          }
          onKeyDown={(e) => {
            if (
              e.key === "Enter" &&
              password &&
              !loading
            ) {
              onConfirm();
            }
          }}
          placeholder="Enter your password"
          className="input mt-3 w-full"
          autoFocus
        />

        <div className="mt-5 flex justify-end gap-3">

          <button
            type="button"
            onClick={onCancel}
            disabled={loading}
            className="px-4 py-2 rounded-xl border border-white/10 text-parchment-400"
          >
            Cancel
          </button>

          <button
            type="button"
            onClick={onConfirm}
            disabled={!password || loading}
            className={`px-4 py-2 rounded-xl text-white font-semibold disabled:opacity-50 ${
              isClosing
                ? "bg-amber-500"
                : "bg-cyan-500"
            }`}
          >
            {loading
              ? "Verifying..."
              : isClosing
              ? "Confirm Close"
              : "Confirm Reopen"}
          </button>

        </div>
      </div>
    </div>
  );
}
function IntroSplash({ onFinish }) {
  const [mounted, setMounted] = useState(false);
  const [exiting, setExiting] = useState(false);

  useEffect(() => {
    const raf = requestAnimationFrame(() => setMounted(true));
    const exitTimer = setTimeout(() => setExiting(true), 1400);
    const doneTimer = setTimeout(() => onFinish(), 2100);

    return () => {
      cancelAnimationFrame(raf);
      clearTimeout(exitTimer);
      clearTimeout(doneTimer);
    };
  }, [onFinish]);

  return (
    <div
      className={`fixed inset-0 z-[100] flex items-center justify-center bg-ink-950 transition-opacity duration-700 ${
        exiting ? "opacity-0 pointer-events-none" : "opacity-100"
      }`}
    >
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,rgba(180,140,60,0.08),transparent_70%)]" />

      <div
        className={`relative flex flex-col items-center transition-all duration-700 ease-out ${
          exiting
            ? "opacity-0 scale-110"
            : mounted
            ? "opacity-100 scale-100"
            : "opacity-0 scale-95"
        }`}
      >
        <div className="flex items-center gap-4">
          <span className="w-2.5 h-2.5 rounded-full bg-brass-300 animate-pulse" />
          <h1 className="text-6xl md:text-8xl font-bold tracking-tight text-white">
            TRACE
          </h1>
          <span className="w-2.5 h-2.5 rounded-full bg-brass-300 animate-pulse" />
        </div>

        <p className="mt-4 text-sm md:text-base tracking-[0.4em] text-brass-300/80 uppercase">
          Digital Evidence Management
        </p>
      </div>
    </div>
  );
}
/* =========================================================
   LANDING PAGE
========================================================= */

function LandingPage({
  selectedRole,
  setSelectedRole,
  onLogin,
  onSignup,
}) {
  // =========================================================
  // HOME PAGE SLIDESHOW
  // =========================================================

  const slides = [
    "/images/trace-slide-1.png",
    "/images/trace-slide-2.png",
    "/images/trace-slide-3.png",
    "/images/trace-slide-4.png",
  ];

  const [currentSlide, setCurrentSlide] = useState(0);

  /*
    We add the first image again at the end.

    This allows the slideshow to move smoothly:

    1 → 2 → 3 → 4 → 1

    instead of suddenly jumping back from 4 to 1.
  */
  const slideshowImages = [
    ...slides,
    slides[0],
  ];

  useEffect(() => {
    let timer;

    /*
      When we reach the duplicate first image,
      wait for the horizontal transition to finish,
      then silently reset back to the real first image.
    */
    if (currentSlide === slides.length) {
      timer = setTimeout(() => {
        setCurrentSlide(0);
      }, 750);
    } else {
      /*
        Every image stays visible for 3 seconds.
      */
      timer = setTimeout(() => {
        setCurrentSlide((prev) => prev + 1);
      }, 3000);
    }

    return () => clearTimeout(timer);
  }, [currentSlide, slides.length]);

  return (
    <div className="min-h-screen bg-ink-950 text-white">

      {/* =====================================================
          NAVIGATION
          FUNCTIONALITY UNCHANGED
      ====================================================== */}

      <nav className="border-b border-white/10 bg-ink-950/80 backdrop-blur-xl sticky top-0 z-30">

        <div className="max-w-7xl mx-auto px-6 py-5 flex items-center justify-between">

          <div className="flex items-center gap-3">

            <div className="w-10 h-10 rounded-xl bg-brass-400/10 border border-cyan-400/30 flex items-center justify-center text-brass-300 text-xl">
              ◈
            </div>

            <div>

              <h1 className="font-bold text-lg">
                TRACE
              </h1>

              <p className="text-xs text-slate-500">
                Digital Evidence Management
              </p>

            </div>

          </div>

          <div className="flex items-center gap-3">

            <button
              onClick={onSignup}
              className="px-5 py-2.5 rounded-xl border border-cyan-400/40 text-brass-300 font-semibold hover:bg-brass-400/10 transition"
            >
              Sign up
            </button>

            <button
              onClick={onLogin}
              className="px-5 py-2.5 rounded-xl bg-brass-400 text-slate-950 font-semibold hover:bg-cyan-300 transition"
            >
              Login
            </button>

          </div>

        </div>

      </nav>


      {/* =====================================================
          HERO SECTION
      ====================================================== */}

      <section className="max-w-7xl mx-auto px-6 pt-14 pb-10 grid lg:grid-cols-2 gap-12 items-center">

        {/* ===================================================
            LEFT SIDE
        ==================================================== */}

        <div>

          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full border border-cyan-400/20 bg-brass-400/5 text-brass-300 text-sm mb-7">

            <span className="w-2 h-2 rounded-full bg-cyan-300 animate-pulse" />

            Secure Digital Document Management

          </div>


          <h2 className="text-5xl md:text-7xl font-bold leading-tight tracking-tight">

            TRACE

            <span className="block text-brass-300">
              every record.
            </span>

          </h2>


          <p className="mt-7 text-lg text-parchment-500 max-w-xl leading-relaxed">

            A secure platform for managing FIRs, investigation
            records, evidence, witness statements, court filings
            and other sensitive legal documents.

          </p>


          <div className="mt-9 flex flex-col sm:flex-row gap-4">

            <button
              onClick={onSignup}
              className="px-7 py-4 rounded-xl bg-brass-400 text-slate-950 font-bold hover:bg-cyan-300 transition"
            >
              Create account →
            </button>

          </div>


          {/* =================================================
    ROLE SELECTION
    FUNCTIONALITY UNCHANGED
================================================== */}

<div className="mt-8 grid sm:grid-cols-3 gap-4">

  {publicRoles.map((role) => {
    const accent = roleAccents[role];
    const isSelected = selectedRole === role;

    const roleInfo = {
      "Police/Investigator": {
        description: "Maintain chain of custody",
        icon: (
          <svg
            viewBox="0 0 64 64"
            className="w-12 h-12"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path
              d="M32 5L51 12V28C51 41 43 52 32 59C21 52 13 41 13 28V12L32 5Z"
              fill="currentColor"
              opacity="0.18"
            />
            <path
              d="M32 5L51 12V28C51 41 43 52 32 59C21 52 13 41 13 28V12L32 5Z"
              stroke="currentColor"
              strokeWidth="3"
            />
            <path
              d="M23 30L29 36L42 22"
              stroke="currentColor"
              strokeWidth="4"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        ),
        iconClass: "text-blue-300",
      },

      "Lawyer/Legal Officer": {
        description: "Manage case files & evidence",
        icon: (
          <svg
            viewBox="0 0 64 64"
            className="w-12 h-12"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path
              d="M18 52H46"
              stroke="currentColor"
              strokeWidth="4"
              strokeLinecap="round"
            />
            <path
              d="M25 52V45H39V52"
              stroke="currentColor"
              strokeWidth="4"
            />
            <path
              d="M32 16V45"
              stroke="currentColor"
              strokeWidth="4"
              strokeLinecap="round"
            />
            <path
              d="M32 16C28 16 25 13 25 9"
              stroke="currentColor"
              strokeWidth="4"
              strokeLinecap="round"
            />
            <path
              d="M32 16C36 16 39 13 39 9"
              stroke="currentColor"
              strokeWidth="4"
              strokeLinecap="round"
            />
            <path
              d="M16 22H48"
              stroke="currentColor"
              strokeWidth="4"
              strokeLinecap="round"
            />
            <path
              d="M12 22L6 35H18L12 22Z"
              fill="currentColor"
              opacity="0.25"
              stroke="currentColor"
              strokeWidth="2"
            />
            <path
              d="M52 22L46 35H58L52 22Z"
              fill="currentColor"
              opacity="0.25"
              stroke="currentColor"
              strokeWidth="2"
            />
          </svg>
        ),
        iconClass: "text-amber-300",
      },

      "Court Authority": {
        description: "Access digital records",
        icon: (
          <svg
            viewBox="0 0 64 64"
            className="w-12 h-12"
            fill="none"
            xmlns="http://www.w3.org/2000/svg"
          >
            <path
              d="M12 55H52"
              stroke="currentColor"
              strokeWidth="4"
              strokeLinecap="round"
            />
            <path
              d="M17 55V30"
              stroke="currentColor"
              strokeWidth="4"
            />
            <path
              d="M29 55V30"
              stroke="currentColor"
              strokeWidth="4"
            />
            <path
              d="M41 55V30"
              stroke="currentColor"
              strokeWidth="4"
            />
            <path
              d="M53 55V30"
              stroke="currentColor"
              strokeWidth="4"
            />
            <path
              d="M9 30H55L32 10L9 30Z"
              fill="currentColor"
              opacity="0.2"
              stroke="currentColor"
              strokeWidth="3"
              strokeLinejoin="round"
            />
          </svg>
        ),
        iconClass: "text-amber-200",
      },
    };

    const info = roleInfo[role];

    return (
      <button
        key={role}
        type="button"
        onClick={() => setSelectedRole(role)}
        className={`group relative overflow-hidden min-h-[112px] px-6 py-5 rounded-2xl border text-left transition-all duration-300 ${
          isSelected
            ? "border-blue-400/70 bg-gradient-to-r from-blue-500/20 via-blue-400/10 to-transparent shadow-lg shadow-blue-500/20"
            : "border-white/10 bg-white/[0.035] hover:border-white/20 hover:bg-white/[0.06]"
        }`}
      >

        {/* Role-specific glow */}
        <div
          className={`absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-500 pointer-events-none ${
            role === "Police/Investigator"
              ? "bg-gradient-to-r from-blue-500/15 to-transparent"
              : role === "Lawyer/Legal Officer"
              ? "bg-gradient-to-r from-amber-400/15 to-transparent"
              : "bg-gradient-to-r from-yellow-300/10 to-transparent"
          }`}
        />

        {/* Content */}
        <div className="relative flex items-center gap-5">

          {/* ICON */}
          <div
            className={`shrink-0 transition-transform duration-300 group-hover:scale-105 ${
              info.iconClass
            }`}
          >
            {info.icon}
          </div>

          {/* TEXT */}
          <div className="min-w-0">

            <p
              className={`text-xl font-semibold transition-colors ${
                isSelected
                  ? "text-white"
                  : "text-slate-200 group-hover:text-white"
              }`}
            >
              {accent.name}
            </p>

            <p className="mt-2 text-sm text-parchment-500 group-hover:text-parchment-400 transition-colors">
              {info.description}
            </p>

          </div>

        </div>

      </button>
    );
  })}

</div>


        </div>


        {/* =====================================================
    RIGHT SIDE — 4 IMAGE SLIDESHOW
====================================================== */}

<div className="relative">

  {/* Background glow */}
  <div className="absolute inset-8 bg-brass-400/10 blur-3xl rounded-full" />

  {/* =================================================
      SLIDESHOW CONTAINER
      STRAIGHT — NO TILT
  ================================================== */}

  <div className="relative overflow-hidden rounded-3xl border border-white/10 bg-ink-950 shadow-2xl">

    {/* =================================================
        SLIDE TRACK
        Horizontal movement
    ================================================== */}

    <div
      className="flex"
      style={{
        transform: `translateX(-${currentSlide * 100}%)`,
        transition:
          currentSlide === 0
            ? "none"
            : "transform 750ms cubic-bezier(0.77, 0, 0.175, 1)",
      }}
    >

      {slideshowImages.map((image, index) => (

        <div
          key={`${image}-${index}`}
          className="min-w-full aspect-[3/2] relative bg-ink-950"
        >

          <img
            src={image}
            alt={`TRACE showcase ${index + 1}`}
            className="absolute inset-0 w-full h-full object-contain"
          />

          {/* Subtle dark overlay */}
          <div className="absolute inset-0 bg-black/10 pointer-events-none" />

          {/* Soft edge vignette */}
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,transparent_40%,rgba(2,6,23,0.25)_100%)] pointer-events-none" />

        </div>

      ))}

    </div>


    {/* =================================================
        SLIDESHOW INDICATORS
    ================================================== */}

    <div className="absolute bottom-5 left-0 right-0 flex justify-center gap-2">

      {slides.map((_, index) => (

        <div
          key={index}
          className={`h-1.5 rounded-full transition-all duration-500 ${
            currentSlide === index
              ? "w-8 bg-cyan-300"
              : "w-2 bg-white/30"
          }`}
        />

      ))}

    </div>

  </div>

</div>

</section>
      {/* =====================================================
          SECURITY STATS
          UNCHANGED
      ====================================================== */}

      <section className="border-y border-white/10 bg-white/[0.02]">

        <div className="max-w-7xl mx-auto px-6 py-12 grid grid-cols-2 md:grid-cols-4 gap-8">

          {[
            ["256-bit", "Data Protection"],
            ["SHA-256", "Integrity Verification"],
            ["JWT", "Secure Authentication"],
            ["24/7", "Audit Visibility"],
          ].map(([value, label]) => (

            <div key={label}>

              <p className="text-2xl font-bold text-brass-300">
                {value}
              </p>

              <p className="text-sm text-slate-500 mt-1">
                {label}
              </p>

            </div>

          ))}

        </div>

      </section>


      {/* =====================================================
          FEATURES
          UNCHANGED
      ====================================================== */}

      <section className="max-w-7xl mx-auto px-6 py-24">

        <div className="max-w-2xl">

          <p className="text-brass-300 font-semibold">
            BUILT FOR CRITICAL RECORDS
          </p>

          <h3 className="text-4xl font-bold mt-3">
            One secure system for the entire document lifecycle.
          </h3>

        </div>


        <div className="grid md:grid-cols-3 gap-6 mt-12">

          {[
            [
              "◈",
              "Centralized Documents",
              "Keep investigation, evidence and legal records organized around cases."
            ],
            [
              "◉",
              "Integrity Protection",
              "Every uploaded document receives a cryptographic SHA-256 fingerprint."
            ],
            [
              "◷",
              "Complete Audit Trail",
              "Track important system activity with user and timestamp information."
            ],
          ].map(([icon, title, text]) => (

            <div
              key={title}
              className="p-7 rounded-2xl border border-white/10 bg-white/[0.03]"
            >

              <div className="text-2xl text-brass-300">
                {icon}
              </div>

              <h4 className="font-bold text-xl mt-5">
                {title}
              </h4>

              <p className="text-slate-500 mt-3 leading-relaxed">
                {text}
              </p>

            </div>

          ))}

        </div>

      </section>


      {/* =====================================================
          FOOTER
      ====================================================== */}

      <footer className="border-t border-white/10 py-8 text-center text-slate-600 text-sm">
        TRACE • Secure Digital Document Management System
      </footer>

    </div>
  );
}
/* =========================================================
   LOGIN
========================================================= */

function LoginModal({
  role,
  setRole,
  email,
  setEmail,
  password,
  setPassword,
  error,
  loading,
  otpStep,
  otp,
  setOtp,
  otpLoading,
  onClose,
  onSubmit,
  onBackToLogin,
}) {
  // =========================================================
  // ROLE-SPECIFIC BACKGROUND IMAGES
  // =========================================================
  const roleBackgrounds = {
    "Police/Investigator": "/images/trace-police-bg.png",
    "Court Authority": "/images/trace-court-bg.png",
    "Lawyer/Legal Officer": "/images/trace-lawyer-bg.png",
  };

  const backgroundImage = roleBackgrounds[role];

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto sih-login-modal">

      {/* =====================================================
          ROLE-SPECIFIC BACKGROUND
      ====================================================== */}
      <div className="fixed inset-0 overflow-hidden bg-ink-950">

        {backgroundImage && (
          <div
            className="absolute inset-0"
            style={{
              backgroundImage: `url("${backgroundImage}")`,

              // Show the complete image across the screen
              // instead of zooming/cropping it.
              backgroundSize: "100% 100%",

              backgroundPosition: "center",
              backgroundRepeat: "no-repeat",

              // Slight blur + brighter image.
              filter: "blur(3px) brightness(1.18) contrast(1.02)",

              // Prevent blurred edges from showing.
              transform: "scale(1.015)",
            }}
          />
        )}

        {/* =================================================
            DARK OVERLAY
        ================================================== */}
        <div
          className={`absolute inset-0 ${
            backgroundImage
              ? "bg-black/30"
              : "bg-ink-950/96"
          }`}
        />

        {/* =================================================
            SUBTLE VIGNETTE
        ================================================== */}
        {backgroundImage && (
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,transparent_15%,rgba(2,6,23,0.22)_100%)]" />
        )}
      </div>

      {/* =====================================================
          LOGIN CARD
      ====================================================== */}
      <div className="relative z-10 min-h-screen flex items-center justify-center p-5">

        <div className="w-full max-w-md bg-ink-950/80 backdrop-blur-xl border border-white/20 rounded-3xl p-8 shadow-2xl">

          {/* =================================================
              HEADER
          ================================================== */}
          <div className="flex items-start justify-between">

            <div>
              <p className="text-brass-300 text-sm font-semibold">
                SECURE ACCESS
              </p>

              <h2 className="text-3xl font-bold mt-2">
                Welcome back
              </h2>
            </div>

            <button
              onClick={onClose}
              className="text-parchment-500 hover:text-white text-xl"
            >
              ×
            </button>

          </div>

          {/* =================================================
              OTP STEP
          ================================================== */}
          {otpStep ? (

            <form
              onSubmit={onSubmit}
              className="space-y-5 mt-8"
            >

              <div className="p-4 rounded-2xl bg-brass-400/5 border border-cyan-400/20">

                <p className="text-brass-300 font-semibold">
                  Two-Factor Authentication
                </p>

                <p className="text-sm text-parchment-500 mt-2">
                  We sent a 6-digit OTP to{" "}
                  <span className="text-slate-200">
                    {email}
                  </span>.
                </p>

              </div>

              <div>

                <label className="text-sm text-parchment-400">
                  Verification Code
                </label>

                <input
                  type="text"
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  maxLength={6}
                  value={otp}
                  onChange={(e) =>
                    setOtp(
                      e.target.value
                        .replace(/\D/g, "")
                        .slice(0, 6)
                    )
                  }
                  placeholder="Enter 6-digit OTP"
                  className="mt-2 w-full px-4 py-4 rounded-xl bg-ink-950/80 border border-white/15 outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400/30 text-center text-2xl tracking-[0.5em]"
                  required
                  autoFocus
                />

              </div>

              {error && (
                <div className="p-3 rounded-xl bg-red-400/10 border border-red-400/20 text-red-300 text-sm">
                  {error}
                </div>
              )}

              <button
                disabled={otpLoading || otp.length !== 6}
                className="w-full py-3.5 rounded-xl bg-brass-400 text-slate-950 font-bold hover:bg-cyan-300 disabled:opacity-50"
              >
                {otpLoading
                  ? "Verifying OTP..."
                  : "Verify OTP →"}
              </button>

              <button
                type="button"
                onClick={onBackToLogin}
                className="w-full text-sm text-parchment-500 hover:text-brass-300"
              >
                ← Back to login
              </button>

            </form>

          ) : (

            /* =================================================
               NORMAL LOGIN
            ================================================== */

            <form
              onSubmit={onSubmit}
              className="space-y-5 mt-8"
            >

              {/* ROLE */}
              <div>

                <label className="text-sm text-parchment-400">
                  Role
                </label>

                <select
                  value={role}
                  onChange={(e) => setRole(e.target.value)}
                  className="mt-2 w-full px-4 py-3 rounded-xl bg-ink-950/85 border border-white/15 outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400/30"
                >

                  <option value="">
                    Use account role
                  </option>

                  {publicRoles.map((item) => (
                    <option
                      key={item}
                      value={item}
                      className="bg-ink-900"
                    >
                      {item}
                    </option>
                  ))}

                </select>

              </div>

              {/* EMAIL */}
              <div>

                <label className="text-sm text-parchment-400">
                  Email
                </label>

                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="admin@sih.com"
                  className="mt-2 w-full px-4 py-3 rounded-xl bg-ink-950/80 border border-white/15 outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400/30"
                  required
                />

              </div>

              {/* PASSWORD */}
              <div>

                <label className="text-sm text-parchment-400">
                  Password
                </label>

                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter password"
                  className="mt-2 w-full px-4 py-3 rounded-xl bg-ink-950/80 border border-white/15 outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400/30"
                  required
                />

              </div>

              {/* ERROR */}
              {error && (
                <div className="p-3 rounded-xl bg-red-400/10 border border-red-400/20 text-red-300 text-sm">
                  {error}
                </div>
              )}

              {/* LOGIN BUTTON */}
              <button
                disabled={loading}
                className="w-full py-3.5 rounded-xl bg-brass-400 text-slate-950 font-bold hover:bg-cyan-300 disabled:opacity-50"
              >
                {loading
                  ? "Authenticating..."
                  : "Secure Login →"}
              </button>

            </form>
          )}

        </div>
      </div>
    </div>
  );
}

/* =========================================================
   SIGN UP
========================================================= */

function SignupModal({
  username,
  setUsername,
  email,
  setEmail,
  password,
  setPassword,
  confirmPassword,
  setConfirmPassword,
  role,
  setRole,
  error,
  loading,
  onClose,
  onSubmit,
  onLogin,
}) {
  const selfRegistrationRoles = publicRoles;

  // Role-specific background images
  const roleBackgrounds = {
    "Police/Investigator": "/images/trace-police-bg.png",
    "Court Authority": "/images/trace-court-bg.png",
    "Lawyer/Legal Officer": "/images/trace-lawyer-bg.png",
  };

  const backgroundImage = roleBackgrounds[role];

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto sih-login-modal">

      {/* =====================================================
          ROLE-SPECIFIC BACKGROUND
      ====================================================== */}
      <div className="fixed inset-0 overflow-hidden bg-ink-950">

        {backgroundImage && (
          <div
            className="absolute inset-0"
            style={{
              backgroundImage: `url("${backgroundImage}")`,

              // Show the complete image across the viewport.
              // This prevents the previous excessive zoom/cropping.
              backgroundSize: "100% 100%",

              backgroundPosition: "center",
              backgroundRepeat: "no-repeat",

              // Reduced blur + increased brightness.
              filter: "blur(3px) brightness(1.18) contrast(1.02)",

              // Prevent blurred edges from appearing.
              transform: "scale(1.015)",
            }}
          />
        )}

        {/* =================================================
            DARK OVERLAY
            Reduced considerably so the image is brighter.
        ================================================== */}
        <div
          className={`absolute inset-0 ${
            backgroundImage
              ? "bg-black/30"
              : "bg-ink-950/96"
          }`}
        />

        {/* =================================================
            SUBTLE VIGNETTE
            Keeps the centre readable without making the
            entire background excessively dark.
        ================================================== */}
        {backgroundImage && (
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,transparent_15%,rgba(2,6,23,0.22)_100%)]" />
        )}
      </div>

      {/* =====================================================
          SIGNUP CARD
      ====================================================== */}
      <div className="relative z-10 min-h-screen flex items-center justify-center p-5">

        <div className="w-full max-w-md bg-ink-950/80 backdrop-blur-xl border border-white/20 rounded-3xl p-8 shadow-2xl my-6">

          {/* HEADER */}
          <div className="flex items-start justify-between">

            <div>
              <p className="text-brass-300 text-sm font-semibold">
                CREATE ACCOUNT
              </p>

              <h2 className="text-3xl font-bold mt-2">
                Join TRACE
              </h2>

              <p className="text-sm text-parchment-500 mt-2">
                Your OTP will be sent only to this registered email address.
              </p>
            </div>

            <button
              onClick={onClose}
              className="text-parchment-500 hover:text-white text-xl"
            >
              ×
            </button>

          </div>

          {/* FORM */}
          <form onSubmit={onSubmit} className="space-y-4 mt-7">

            {/* FULL NAME */}
            <div>
              <label className="text-sm text-parchment-400">
                Full name / username
              </label>

              <input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="name"
                placeholder="Your name"
                minLength={3}
                maxLength={100}
                className="mt-2 w-full px-4 py-3 rounded-xl bg-ink-950/80 border border-white/15 outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400/30"
                required
              />
            </div>

            {/* EMAIL */}
            <div>
              <label className="text-sm text-parchment-400">
                Official email address
              </label>

              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoComplete="email"
                placeholder="name@organization.gov.in"
                className="mt-2 w-full px-4 py-3 rounded-xl bg-ink-950/80 border border-white/15 outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400/30"
                required
              />
            </div>

            {/* ROLE */}
            <div>
              <label className="text-sm text-parchment-400">
                Role
              </label>

              <select
                value={role}
                onChange={(e) => setRole(e.target.value)}
                className="mt-2 w-full px-4 py-3 rounded-xl bg-ink-950/85 border border-white/15 outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400/30"
                required
              >
                <option value="">
                  Select role
                </option>

                {selfRegistrationRoles.map((item) => (
                  <option
                    key={item}
                    value={item}
                    className="bg-ink-900"
                  >
                    {item}
                  </option>
                ))}
              </select>

              <p className="text-xs text-slate-500 mt-2">
                Administrator accounts are created by the organization.
              </p>
            </div>

            {/* PASSWORD */}
            <div>
              <label className="text-sm text-parchment-400">
                Password
              </label>

              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="new-password"
                placeholder="At least 10 characters"
                minLength={10}
                maxLength={128}
                className="mt-2 w-full px-4 py-3 rounded-xl bg-ink-950/80 border border-white/15 outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400/30"
                required
              />
            </div>

            {/* CONFIRM PASSWORD */}
            <div>
              <label className="text-sm text-parchment-400">
                Confirm password
              </label>

              <input
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                autoComplete="new-password"
                placeholder="Re-enter password"
                minLength={10}
                maxLength={128}
                className="mt-2 w-full px-4 py-3 rounded-xl bg-ink-950/80 border border-white/15 outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400/30"
                required
              />
            </div>

            {/* ERROR */}
            {error && (
              <div className="p-3 rounded-xl bg-red-400/10 border border-red-400/20 text-red-300 text-sm">
                {error}
              </div>
            )}

            {/* CREATE ACCOUNT */}
            <button
              disabled={loading}
              className="w-full py-3.5 rounded-xl bg-brass-400 text-slate-950 font-bold hover:bg-cyan-300 disabled:opacity-50"
            >
              {loading
                ? "Creating account..."
                : "Create secure account →"}
            </button>

            {/* LOGIN */}
            <button
              type="button"
              onClick={onLogin}
              className="w-full text-sm text-parchment-500 hover:text-brass-300"
            >
              Already registered? Log in
            </button>

          </form>
        </div>
      </div>
    </div>
  );
}

/* =========================================================
   DASHBOARD LAYOUT
========================================================= */

function DashboardLayout({
  page,
  setPage,
  user,
  logout,
  children,
}) {
  const allowedNavItems = visibleNavItems(user);
  const currentNavItem = allowedNavItems.find((item) => item.id === page) || allowedNavItems[0];

  return (
    <div className="min-h-screen bg-ink-950 text-white flex">
      <aside className="hidden md:flex w-64 border-r border-white/10 flex-col bg-ink-950">
        <div className="p-6 border-b border-white/10">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-brass-400/10 text-brass-300 flex items-center justify-center">
              ◈
            </div>

            <div>
              <p className="font-bold">TRACE</p>
              <p className="text-xs text-slate-600">
                Control Center
              </p>
            </div>
          </div>
        </div>

        <nav className="p-4 space-y-1 flex-1">
          {allowedNavItems.map((item) => (
            <button
              key={item.id}
              onClick={() => setPage(item.id)}
              className={`w-full flex items-center gap-3 px-4 py-3 rounded-xl text-left transition ${
                page === item.id
                  ? "bg-brass-400/10 text-brass-300"
                  : "text-slate-500 hover:text-white hover:bg-white/5"
              }`}
            >
              <span>{item.icon}</span>
              {item.label}
            </button>
          ))}
        </nav>

        <div className="p-4 border-t border-white/10">
          <div className="px-4 py-3">
            <p className="font-semibold truncate">
              {user?.username}
            </p>

            <p className="text-xs text-brass-300 mt-1">
              {user?.role}
            </p>
          </div>

          <button
            onClick={logout}
            className="w-full mt-2 px-4 py-3 rounded-xl text-left text-red-300 hover:bg-red-400/10"
          >
            ↪ Logout
          </button>
        </div>
      </aside>

      <main className="flex-1 min-w-0">
        <header className="h-20 border-b border-white/10 flex items-center justify-between px-6 md:px-10">
          <div>
            <p className="text-sm text-slate-600">
              SECURE DMS
            </p>

            <h1 className="font-bold text-xl">
              {currentNavItem?.label}
            </h1>
          </div>

          <div className="flex items-center gap-3">
            <div className="hidden sm:block text-right">
              <p className="text-sm font-semibold">
                {user?.username}
              </p>
              <p className="text-xs text-slate-600">
                {user?.role}
              </p>
            </div>

            <div className="w-10 h-10 rounded-full bg-brass-400/10 border border-cyan-400/20 flex items-center justify-center text-brass-300">
              {user?.username?.charAt(0)?.toUpperCase()}
            </div>
          </div>
        </header>

        <div className="p-6 md:p-10">
          {children}
        </div>
      </main>
    </div>
  );
}


/* =========================================================
   DASHBOARD
========================================================= */

function DashboardHome({
  user,
  stats,
  cases,
  loadCases,
  onViewAlerts,
}) {
  useEffect(() => {
    loadCases();
  }, []);

  const admin = isAdmin(user);
  const roleName = user?.role || "User";
  const statCards = admin
    ? [
        ["Active Users", Number.isFinite(Number(stats.users)) ? Number(stats.users) : 0, "♙"],
        ["Total Cases", stats.cases, "◈"],
        ["Total Documents", stats.documents, "▤"],
        ["Audit Events", stats.audit_events, "◷"],
      ]
    : [
        ["My Cases", stats.cases, "◈"],
        ["My Documents", stats.documents, "▤"],
        ["My Audit Events", stats.audit_events, "◷"],
        ["Open Alerts", stats.open_security_alerts, "◉"],
      ];

  return (
    <div>
      <div className="mb-10">
        <p className="text-brass-300 text-sm font-semibold">
          GOOD TO SEE YOU
        </p>

        <h2 className="text-4xl font-bold mt-2">
          Welcome, {user?.username}
        </h2>

        <p className="text-slate-500 mt-2">
          {admin
            ? "System-wide monitoring and administrator controls."
            : `${roleName} workspace with only your authorized records and actions.`}
        </p>
      </div>

      <div className="grid sm:grid-cols-2 xl:grid-cols-4 gap-5">
        {statCards.map(([title, value, icon]) => (
          <StatCard
            key={title}
            title={title}
            value={value}
            icon={icon}
          />
        ))}
      </div>

      {Number(stats.open_security_alerts) > 0 && (
        <button
          onClick={onViewAlerts}
          className="mt-6 w-full text-left p-5 rounded-2xl border border-red-400/30 bg-red-400/10 hover:bg-red-400/15 transition-colors"
        >
          <p className="font-bold text-red-300">
            ⚠ {stats.open_security_alerts} open security alert{Number(stats.open_security_alerts) === 1 ? "" : "s"}
          </p>
          <p className="text-sm text-red-200/80 mt-1">
            An integrity incident needs review. Open Security Center to see the affected document.
          </p>
        </button>
      )}

      <div className="grid lg:grid-cols-2 gap-6 mt-8">
        <div className="p-6 rounded-2xl border border-white/10 bg-white/[0.03]">
          <div className="flex justify-between items-center">
            <h3 className="font-bold text-lg">
              Recent Cases
            </h3>

            <span className="text-xs text-emerald-300">
              LIVE DATA
            </span>
          </div>

          <div className="mt-6 space-y-3">
            {cases.length === 0 ? (
              <p className="text-slate-600">
                No cases created yet.
              </p>
            ) : (
              cases.slice(0, 5).map((item) => (
                <div
                  key={item.id}
                  className="p-4 rounded-xl bg-black/20 border border-white/5 flex justify-between"
                >
                  <div>
                    <p className="font-semibold">
                      {item.case_number}
                    </p>

                    <p className="text-sm text-slate-500">
                      {item.title}
                    </p>
                  </div>

                  <span className="text-xs text-emerald-300">
                    {item.status}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="p-6 rounded-2xl border border-white/10 bg-white/[0.03]">
          <h3 className="font-bold text-lg">
            Security Status
          </h3>

          <div className="mt-6 space-y-4">
            <SecurityRow
              label="JWT Authentication"
              status="Active"
            />

            <SecurityRow
              label="OTP Two-Factor Authentication"
              status="Enabled"
            />

            <SecurityRow
              label="Document Integrity"
              status="SHA-256"
            />

            <SecurityRow
              label="Azure Blob Storage"
              status="Connected"
            />

            <SecurityRow
              label="Audit Logging"
              status="Active"
            />
          </div>
        </div>
      </div>
    </div>
  );
}


/* =========================================================
   ACTIVE CASE USERS
========================================================= */

function ActiveUsersPage({ users, loading, onRefresh }) {
  return (
    <div>
      <div className="flex flex-col sm:flex-row justify-between gap-4 mb-8">
        <div>
          <p className="text-brass-300 text-sm font-semibold">
            ADMIN ONLY
          </p>

          <h2 className="text-3xl font-bold mt-2">
            Active Case Users
          </h2>

          <p className="text-slate-500 mt-2">
            Review users with document, activity and alert counts.
          </p>
        </div>

        <button
          onClick={onRefresh}
          disabled={loading}
          className="px-4 py-3 rounded-xl border border-white/10 text-parchment-400 hover:bg-white/5 disabled:opacity-50"
        >
          {loading ? "Refreshing..." : "Refresh"}
        </button>
      </div>

      {loading ? (
        <p className="text-slate-500">Loading users...</p>
      ) : users.length === 0 ? (
        <EmptyState text="No active users found." />
      ) : (
        <div className="grid lg:grid-cols-2 gap-4">
          {users.map((item) => (
            <div
              key={item.id}
              className="p-5 rounded-2xl border border-white/10 bg-white/[0.03]"
            >
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="font-bold">{item.username}</p>
                  <p className="text-sm text-slate-500 mt-1">{item.email}</p>
                  <p className="text-xs text-brass-300 mt-2">{item.role}</p>
                </div>

                <span className="px-3 py-1 rounded-full bg-emerald-400/10 text-emerald-300 text-xs">
                  Active
                </span>
              </div>

              <div className="grid grid-cols-3 gap-3 mt-5 text-center">
                <MiniStat label="Docs" value={item.documents} />
                <MiniStat label="Events" value={item.audit_events} />
                <MiniStat label="Alerts" value={item.open_alerts} />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/* =========================================================
   CASES
========================================================= */
function CasesPage({
  cases,
  showForm,
  setShowForm,
  newCase,
  setNewCase,
  createCase,
  onDeleteCase,
  onCloseCase,
  onReopenCase,
}) {
  return (
    <div>
      {/* HEADER */}
      <div className="flex flex-col sm:flex-row justify-between gap-4 mb-8">
        <div>
          <h2 className="text-3xl font-bold">
            Case Management
          </h2>

          <p className="text-slate-500 mt-2">
            Manage investigations and legal cases.
          </p>
        </div>

        <button
          onClick={() => setShowForm(!showForm)}
          className="px-5 py-3 rounded-xl bg-brass-400 text-slate-950 font-bold"
        >
          + New Case
        </button>
      </div>

      {/* CREATE CASE FORM */}
      {showForm && (
        <form
          onSubmit={createCase}
          className="mb-8 p-6 rounded-2xl border border-cyan-400/20 bg-brass-400/5 space-y-4"
        >
          <h3 className="font-bold text-xl">
            Create New Case
          </h3>

          <div className="grid md:grid-cols-2 gap-4">
            <input
              placeholder="Case Number"
              value={newCase.case_number}
              onChange={(e) =>
                setNewCase({
                  ...newCase,
                  case_number: e.target.value,
                })
              }
              className="input"
              required
            />

            <input
              placeholder="Case Title"
              value={newCase.title}
              onChange={(e) =>
                setNewCase({
                  ...newCase,
                  title: e.target.value,
                })
              }
              className="input"
              required
            />
          </div>

          <textarea
            placeholder="Case Description"
            value={newCase.description}
            onChange={(e) =>
              setNewCase({
                ...newCase,
                description: e.target.value,
              })
            }
            className="input min-h-28"
          />

          <button
            type="submit"
            className="px-5 py-3 rounded-xl bg-brass-400 text-slate-950 font-bold"
          >
            Create Case
          </button>
        </form>
      )}

      {/* CASE LIST */}
      <div className="space-y-4">
        {cases.length === 0 ? (
          <EmptyState text="No cases available." />
        ) : (
          cases.map((item) => {
            const isClosed = item.status === "Closed";

            return (
              <div
                key={item.id}
                className="p-6 rounded-2xl border border-white/10 bg-white/[0.03] flex flex-col md:flex-row md:items-center justify-between gap-4"
              >
                {/* CASE INFORMATION */}
                <div>
                  <p className="text-brass-300 text-sm font-semibold">
                    {item.case_number}
                  </p>

                  <h3 className="text-xl font-bold mt-1">
                    {item.title}
                  </h3>

                  <p className="text-slate-500 mt-2">
                    {item.description}
                  </p>
                </div>

                {/* STATUS + ACTIONS */}
                <div className="flex flex-col md:items-end gap-3">

                  {/* STATUS */}
                  <span
                    className={`px-3 py-1 rounded-full text-sm w-fit ${
                      isClosed
                        ? "bg-slate-400/10 text-parchment-400"
                        : "bg-emerald-400/10 text-emerald-300"
                    }`}
                  >
                    {isClosed ? "Closed" : "Active"}
                  </span>

                  {/* ACTION BUTTONS */}
                  <div className="flex gap-3">

                    {/* CLOSE / REOPEN */}
                    {isClosed ? (
                      <button
                        type="button"
                        onClick={() =>
                          onReopenCase(
                            item.id,
                            item.case_number
                          )
                        }
                        className="px-4 py-2 rounded-xl border border-cyan-400/20 text-brass-300 hover:bg-brass-400/10"
                      >
                        Reopen Case
                      </button>
                    ) : (
                      <button
                        type="button"
                        onClick={() =>
                          onCloseCase(
                            item.id,
                            item.case_number
                          )
                        }
                        className="px-4 py-2 rounded-xl border border-amber-400/20 text-amber-300 hover:bg-amber-400/10"
                      >
                        Close Case
                      </button>
                    )}

                    {/* DELETE */}
                    <button
                      type="button"
                      onClick={() =>
                        onDeleteCase(
                          item.id,
                          item.case_number
                        )
                      }
                      className="px-4 py-2 rounded-xl border border-red-400/20 text-red-300 hover:bg-red-400/10"
                    >
                      Delete
                    </button>

                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
/* =========================================================
   DOCUMENTS
========================================================= */

function DocumentsPage({
  documents,
  onDeleteDocument,
  cases,
  uploadCaseId,
  setUploadCaseId,
  documentType,
  setDocumentType,
  selectedFile,
  setSelectedFile,
  uploadDocument,
  uploading,
  uploadMessage,
  verifyDocument,
}) {
  const selectedCase = cases.find(
    (item) => String(item.id) === String(uploadCaseId)
  );

  const selectedCaseClosed =
    selectedCase?.status === "Closed";

  return (
    <div>
      {/* HEADER */}
      <div className="mb-8">
        <h2 className="text-3xl font-bold">
          Document Vault
        </h2>

        <p className="text-slate-500 mt-2">
          Upload, manage and verify sensitive case documents.
        </p>
      </div>

      {/* UPLOAD */}
      <form
        onSubmit={uploadDocument}
        className="p-6 rounded-2xl border border-white/10 bg-white/[0.03] mb-8"
      >
        <h3 className="text-xl font-bold">
          Upload Document
        </h3>

        <div className="grid md:grid-cols-3 gap-4 mt-5">

          <select
            value={uploadCaseId}
            onChange={(e) =>
              setUploadCaseId(e.target.value)
            }
            className="input"
            required
          >
            <option value="">
              Select Case
            </option>

            {cases
              .filter(
                (item) => item.status !== "Closed"
              )
              .map((item) => (
                <option
                  key={item.id}
                  value={item.id}
                  className="bg-ink-900"
                >
                  {item.case_number}
                </option>
              ))}
          </select>

          <select
            value={documentType}
            onChange={(e) =>
              setDocumentType(e.target.value)
            }
            className="input"
          >
            <option>Evidence</option>
            <option>FIR</option>
            <option>Police Report</option>
            <option>Witness Statement</option>
            <option>Forensic Report</option>
            <option>Charge Sheet</option>
            <option>Court Filing</option>
            <option>Judgment</option>
            <option>General</option>
          </select>

          <input
            type="file"
            onChange={(e) =>
              setSelectedFile(e.target.files[0])
            }
            className="input file:mr-3 file:px-3 file:py-2 file:rounded-lg file:border-0 file:bg-brass-400 file:text-slate-950"
            required
          />
        </div>

        <button
          disabled={
            uploading ||
            !uploadCaseId ||
            selectedCaseClosed
          }
          className="mt-5 px-5 py-3 rounded-xl bg-brass-400 text-slate-950 font-bold disabled:opacity-50"
        >
          {uploading
            ? "Uploading..."
            : "Upload→"}
        </button>

        {uploadMessage && (
          <div className="mt-4 p-4 rounded-xl bg-ink-950 text-sm text-brass-300 break-all">
            {uploadMessage}
          </div>
        )}
      </form>

      {/* DOCUMENT LIST */}
      <div className="space-y-4">

        {documents.length === 0 ? (
          <EmptyState text="No documents uploaded yet." />
        ) : (
          documents.map((doc) => {

            const caseForDocument = cases.find(
              (c) => c.id === doc.case_id
            );

            const isCaseClosed =
              caseForDocument?.status === "Closed";

            return (
              <div
                key={doc.id}
                className={`p-5 rounded-2xl border bg-white/[0.03] ${
                  isCaseClosed
                    ? "border-slate-600/30 opacity-70"
                    : "border-white/10"
                }`}
              >

                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">

                  {/* DOCUMENT INFO */}
                  <div>
                    <h3 className="font-bold">
                      {doc.filename}
                    </h3>

                    <p className="text-sm text-slate-500 mt-1">
                      {doc.document_type}
                    </p>

                    <p className="text-sm text-slate-500 mt-2">
                      Case Number:{" "}
                      {caseForDocument?.case_number ||
                        "N/A"}
                    </p>

                    <p className="text-sm text-slate-500 mt-1">
                      Date:{" "}
                      {doc.uploaded_at
                        ? new Date(
                            doc.uploaded_at
                          ).toLocaleDateString()
                        : "N/A"}
                    </p>

                    {isCaseClosed && (
                      <p className="text-sm text-amber-300 mt-2">
                        🔒 Case Closed — Document Locked
                      </p>
                    )}
                  </div>

                  {/* ACTIONS */}
                  <div className="flex gap-3">

                    <button
                      type="button"
                      disabled={isCaseClosed}
                      onClick={() =>
                        verifyDocument(doc.id)
                      }
                      className="px-4 py-2 rounded-xl border border-emerald-400/20 text-emerald-300 hover:bg-emerald-400/10 disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                      ✓ Verify Integrity
                    </button>

                    <button
                      type="button"
                      disabled={isCaseClosed}
                      onClick={() =>
                        onDeleteDocument(
                          doc.id,
                          doc.filename
                        )
                      }
                      className="px-4 py-2 rounded-xl border border-red-400/20 text-red-300 hover:bg-red-400/10 disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                      Delete
                    </button>

                  </div>
                </div>
              </div>
            );
          })
        )}

      </div>
    </div>
  );
}

/* =========================================================
   SEARCH
========================================================= */

function SearchPage({
  query,
  setQuery,
  search,
  results,
  documents,
  openDocument,
}) {
  /*
    If nothing is being searched:
    show ALL documents.

    If a search query exists:
    show ONLY filtered search results.
  */
  const displayedDocuments = query.trim()
    ? results
    : documents;

  return (
    <div>
      <div className="mb-8">
        <p className="text-brass-300 text-sm font-semibold">
          DOCUMENT LOOKUP
        </p>

        <h2 className="text-3xl font-bold mt-2">
          Document Search
        </h2>

        <p className="text-slate-500 mt-2">
          Search by file name, document type, case number, title or description.
        </p>
      </div>

      {/* SEARCH BAR */}
      <div className="flex gap-3">
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") search();
          }}
          placeholder="Search documents..."
          className="input flex-1"
        />

        <button
          onClick={search}
          className="px-6 rounded-xl bg-brass-400 text-slate-950 font-bold"
        >
          Search
        </button>
      </div>

      {/* DOCUMENT LIST */}
      <div className="mt-8 space-y-3">

        {displayedDocuments.map((doc) => (
          <div
            key={doc.id}
            onClick={() => openDocument(doc.id, doc.filename)}
            className="p-5 rounded-2xl border border-white/10 bg-white/[0.03] cursor-pointer hover:bg-white/[0.07] hover:border-cyan-400/30 transition"
          >
            <div className="flex items-center justify-between gap-4">

              <div>
                <p className="font-bold">
                  {doc.filename}
                </p>

                <p className="text-sm text-slate-500 mt-1">
                  {doc.document_type}
                </p>
              </div>

              <div className="text-brass-300 text-sm font-semibold shrink-0">
                Open →
              </div>

            </div>
          </div>
        ))}

        {/* NO SEARCH RESULTS */}
        {query.trim() && results.length === 0 && (
          <EmptyState text="No matching documents found." />
        )}

        {/* NO DOCUMENTS AT ALL */}
        {!query.trim() && documents.length === 0 && (
          <EmptyState text="No documents uploaded yet." />
        )}

      </div>
    </div>
  );
}

/* =========================================================
   AUDIT
========================================================= */

function AuditPage({ logs }) {
  return (
    <div>
      <div className="mb-8">
        <p className="text-brass-300 text-sm font-semibold">
          ACCOUNTABILITY
        </p>

        <h2 className="text-3xl font-bold mt-2">
          Audit Trail
        </h2>

        <p className="text-slate-500 mt-2">
          Track important activity across the secure system.
        </p>
      </div>

      <div className="space-y-3">
        {logs.length === 0 ? (
          <EmptyState text="No audit events yet." />
        ) : (
          logs.map((log) => (
            <div
              key={log.id}
              className="p-5 rounded-2xl border border-white/10 bg-white/[0.03] flex gap-4"
            >
              <div className="w-10 h-10 shrink-0 rounded-xl bg-brass-400/10 text-brass-300 flex items-center justify-center">
                ◷
              </div>

              <div>
                <p className="font-bold">
                  {log.action}
                </p>

                <p className="text-sm text-slate-500 mt-1">
                  {log.details}
                </p>

                <p className="text-xs text-slate-700 mt-2">
                  {formatLocalDateTime(log.timestamp)}
                </p>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}


/* =========================================================
   SECURITY
========================================================= */

function SecurityPage({ user, alerts, loading, onRefresh, onUpdateAlert }) {
  const openAlerts = alerts.filter((alert) => alert.status === "OPEN");

  return (
    <div>
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-5 mb-8">
        <div>
          <p className="text-brass-300 text-sm font-semibold">
            SECURITY CENTER
          </p>

          <h2 className="text-3xl font-bold mt-2">
            Security & Integrity
          </h2>

          <p className="text-slate-500 mt-2">
            Review active document-integrity incidents and access protections.
          </p>
        </div>

        <button
          onClick={onRefresh}
          disabled={loading}
          className="px-4 py-3 rounded-xl border border-white/10 text-parchment-400 hover:bg-white/5 disabled:opacity-50"
        >
          {loading ? "Refreshing..." : "↻ Refresh alerts"}
        </button>
      </div>

      <div className="mb-8 p-6 rounded-2xl border border-red-400/25 bg-red-400/10">
        <p className="text-sm font-semibold text-red-200">OPEN INTEGRITY INCIDENTS</p>
        <p className="text-4xl font-bold text-red-300 mt-2">{openAlerts.length}</p>
        <p className="text-sm text-red-100/70 mt-2">
          A changed, deleted, or unavailable Azure document is preserved as a security incident for review.
        </p>
      </div>

      <div className="mb-8">
        <h3 className="font-bold text-lg mb-4">Security alerts</h3>
        {loading ? (
          <p className="text-slate-500">Loading alerts...</p>
        ) : alerts.length === 0 ? (
          <div className="p-5 rounded-2xl border border-emerald-400/20 bg-emerald-400/5 text-emerald-200">
            No open integrity incidents. Your accessible documents currently match their saved fingerprints.
          </div>
        ) : (
          <div className="space-y-4">
            {alerts.map((alert) => (
              <div key={alert.id} className="p-5 rounded-2xl border border-red-400/25 bg-red-400/5">
                <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
                  <div>
                    <p className="font-bold text-red-200">⚠ {alert.type}</p>
                    <p className="text-sm text-parchment-400 mt-2">{alert.details}</p>
                  </div>
                  <span className="w-fit px-3 py-1 rounded-full text-xs font-semibold bg-red-400/15 text-red-200">
                    {alert.severity} · {alert.status}
                  </span>
                </div>
                <div className="mt-4 grid sm:grid-cols-3 gap-3 text-xs text-parchment-500">
                  <span>Document ID: {alert.document_id}</span>
                  <span>Case ID: {alert.case_id}</span>
                  <span>Detected: {formatLocalDateTime(alert.detected_at)}</span>
                </div>
                {alert.resolved_at && (
                  <p className="mt-3 text-xs text-slate-500">
                    Reviewed/Dismissed: {formatLocalDateTime(alert.resolved_at)}
                  </p>
                )}
                <div className="mt-5 flex flex-wrap gap-3">
                  <button
                    onClick={() => onUpdateAlert(alert.id, "review")}
                    disabled={alert.status !== "OPEN"}
                    className="px-4 py-2 rounded-xl border border-emerald-400/20 text-emerald-300 hover:bg-emerald-400/10 disabled:opacity-40"
                  >
                    Mark reviewed
                  </button>

                  <button
                    onClick={() => onUpdateAlert(alert.id, "dismiss")}
                    className="px-4 py-2 rounded-xl border border-white/10 text-parchment-400 hover:bg-white/5"
                  >
                    Dismiss
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="grid md:grid-cols-2 gap-5">
        <SecurityCard
          title="Authenticated Identity"
          value={user?.email}
          description="Authenticated through JWT-based access control."
        />

        <SecurityCard
          title="Assigned Role"
          value={user?.role}
          description="Role is validated by the backend during login."
        />

        <SecurityCard
          title="Document Integrity"
          value="SHA-256"
          description="Stored documents can be cryptographically verified."
        />

        <SecurityCard
          title="Cloud Storage"
          value="Azure Blob"
          description="Documents are stored in Azure Blob Storage."
        />
      </div>
    </div>
  );
}


/* =========================================================
   SMALL COMPONENTS
========================================================= */

function StatCard({ title, value, icon }) {
  return (
    <div className="p-6 rounded-2xl border border-white/10 bg-white/[0.03]">
      <div className="flex justify-between">
        <p className="text-slate-500 text-sm">
          {title}
        </p>

        <span className="text-brass-300">
          {icon}
        </span>
      </div>

      <p className="text-3xl font-bold mt-5">
        {value}
      </p>
    </div>
  );
}


function MiniStat({ label, value }) {
  return (
    <div className="p-3 rounded-xl bg-black/20 border border-white/5">
      <p className="text-xl font-bold text-brass-300">
        {value}
      </p>
      <p className="text-xs text-slate-500 mt-1">
        {label}
      </p>
    </div>
  );
}


function SecurityRow({ label, status }) {
  return (
    <div className="flex items-center justify-between p-4 rounded-xl bg-black/20">
      <span className="text-parchment-500">
        {label}
      </span>

      <span className="text-xs text-emerald-300">
        ● {status}
      </span>
    </div>
  );
}


function SecurityCard({
  title,
  value,
  description,
}) {
  return (
    <div className="p-6 rounded-2xl border border-white/10 bg-white/[0.03]">
      <p className="text-slate-500 text-sm">
        {title}
      </p>

      <p className="text-xl font-bold text-brass-300 mt-3">
        {value}
      </p>

      <p className="text-slate-600 text-sm mt-3">
        {description}
      </p>
    </div>
  );
}


function EmptyState({ text }) {
  return (
    <div className="p-10 rounded-2xl border border-dashed border-white/10 text-center text-slate-600">
      {text}
    </div>
  );
}


export default App;
